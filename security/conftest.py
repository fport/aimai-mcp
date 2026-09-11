"""Two servers in two processes, started for real.

These tests do not import the server. They cannot: it resolves mcp 2.x and
this environment resolves mcp 1.x, which is the arrangement under test. So the
fixture starts the server with the *other* environment's interpreter and talks
to it over HTTP, exactly as a deployment would.

That makes the suite slower than an in-process fake and worth it: an in-process
fake would pass on a day when the two SDKs had stopped interoperating, and the
claim being made here is precisely that they have not.
"""

from __future__ import annotations

import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SERVER_DIR = ROOT / "server"
SERVER_PYTHON = SERVER_DIR / ".venv" / "bin" / "python"
CORPUS = Path(__file__).resolve().parent / "corpus" / "injection.jsonl"

TOKENS = (
    "tok-acme-viewer:acme:viewer,"
    "tok-acme-analyst:acme:analyst,"
    "tok-acme-admin:acme:admin,"
    "tok-acme-readonly:acme:analyst:reader,"
    "tok-globex-analyst:globex:analyst,"
    "tok-globex-admin:globex:admin"
)


def load_corpus(vector: str | None = None) -> list[dict]:
    """The corpus, optionally narrowed to one attack surface.

    `vector` says *where* a record is planted: `ticket_note` records arrive as
    customer text through a tool result, `tool_description` records arrive as
    the server's own description of a tool. Different surface, different
    control -- the plan lock for the first, the pin check for the second -- so
    the suites that assert on them are different too.
    """
    records = [
        json.loads(line)
        for line in CORPUS.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if vector is None:
        return records
    return [r for r in records if r["vector"] == vector]


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_for(url: str, process: subprocess.Popen, timeout: float = 30.0) -> None:
    """Wait until the port answers, or fail with the server's own output."""
    import httpx

    deadline = time.time() + timeout
    while time.time() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"server exited with {process.returncode}:\n{_drain(process)}"
            )
        try:
            # 401 is the healthy answer here: the server is up and refusing an
            # unauthenticated request, which is the behaviour under test.
            httpx.get(url, timeout=1.0)
            return
        except httpx.HTTPError:
            time.sleep(0.2)
    process.terminate()
    raise RuntimeError(f"{url} did not come up in {timeout}s:\n{_drain(process)}")


def _drain(process: subprocess.Popen) -> str:
    try:
        out, _ = process.communicate(timeout=2)
    except subprocess.TimeoutExpired:  # pragma: no cover - defensive
        process.kill()
        out, _ = process.communicate()
    return (out or b"").decode("utf-8", "replace")[-4000:]


@pytest.fixture(scope="session")
def server_python() -> Path:
    if not SERVER_PYTHON.exists():
        pytest.skip(
            f"{SERVER_PYTHON} is missing. The server resolves mcp 2.x in its own "
            "environment; run `uv sync --group dev` inside server/ first."
        )
    return SERVER_PYTHON


@pytest.fixture(scope="session")
def seeded_db(tmp_path_factory) -> Path:
    """A fresh database with every corpus record planted as a customer note.

    The corpus lives in one file and is read here, so a record added to the
    JSONL is in the database, in the parametrized tests and in the results
    table without being written down three times.
    """
    path = tmp_path_factory.mktemp("db") / "support.sqlite3"
    subprocess.run(
        [
            str(SERVER_PYTHON),
            "-c",
            f"from aimai_mcp_server import db; db.seed({str(path)!r})",
        ],
        cwd=SERVER_DIR,
        check=True,
        capture_output=True,
    )

    conn = sqlite3.connect(path)
    try:
        for index, record in enumerate(load_corpus("ticket_note")):
            ticket = ticket_for(index)
            conn.execute(
                "INSERT INTO tickets VALUES (?, ?, ?, ?, 'open', 'normal', ?)",
                ("acme", ticket, "C-100", f"corpus: {record['id']}", "2026-08-10"),
            )
            conn.execute(
                "INSERT INTO ticket_notes"
                " (tenant_id, note_id, ticket_id, author, body, from_customer)"
                " VALUES (?, ?, ?, 'customer', ?, 1)",
                ("acme", f"CORPUS-{index}", ticket, record["text"]),
            )
        conn.commit()
    finally:
        conn.close()
    return path


# One ticket per corpus record, so a run that reads the notes of a ticket
# reads exactly one attack and the result is attributable to it.
CORPUS_TICKET_BASE = 5000


def ticket_for(index: int) -> str:
    return f"T-{CORPUS_TICKET_BASE + index}"


@pytest.fixture(scope="session")
def servers(server_python, seeded_db, tmp_path_factory):
    """Reader and writer, running, with an audit log the tests can read."""
    audit = tmp_path_factory.mktemp("audit") / "audit.jsonl"
    ports = {"reader": free_port(), "writer": free_port()}
    processes: dict[str, subprocess.Popen] = {}

    for role, port in ports.items():
        env = {
            **os.environ,
            "AIMAI_MCP_DB": str(seeded_db),
            "AIMAI_MCP_TOKENS": TOKENS,
            "AIMAI_MCP_AUDIT": str(audit),
            "AIMAI_MCP_AUDIT_SALT": "test-salt",
            "AIMAI_MCP_ISSUER": f"http://127.0.0.1:{ports['reader']}",
            "AIMAI_MCP_WRITER_ISSUER": f"http://127.0.0.1:{ports['writer']}",
            "AIMAI_MCP_FETCH_ALLOWLIST": "status.example.com",
        }
        processes[role] = subprocess.Popen(
            [
                str(server_python),
                "-m",
                "aimai_mcp_server",
                "--role",
                role,
                "--port",
                str(port),
                "--db",
                str(seeded_db),
            ],
            cwd=SERVER_DIR,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

    try:
        for role, port in ports.items():
            _wait_for(f"http://127.0.0.1:{port}/mcp", processes[role])
        yield {
            "reader_url": f"http://127.0.0.1:{ports['reader']}/mcp",
            "writer_url": f"http://127.0.0.1:{ports['writer']}/mcp",
            "audit": audit,
            "db": seeded_db,
        }
    finally:
        for process in processes.values():
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:  # pragma: no cover - defensive
                process.kill()


@pytest.fixture
def pins_path() -> Path:
    return ROOT / "agent" / "pins.json"


def pytest_report_header(config):  # pragma: no cover - reporting only
    return (
        f"security: client mcp in {sys.executable}, "
        f"server mcp in {SERVER_PYTHON if SERVER_PYTHON.exists() else 'MISSING'}"
    )
