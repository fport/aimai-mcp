"""Starting the two servers, in one place.

Both the test fixtures and the measurement script need a reader and a writer
running in the *server's* environment while the caller lives in the agent's.
Duplicating that in two files is how the suite and the numbers end up
measuring slightly different systems.
"""

from __future__ import annotations

import json
import os
import socket
import sqlite3
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path

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

# One ticket per corpus record, so a run that reads a ticket's notes reads
# exactly one attack and the outcome is attributable to it.
CORPUS_TICKET_BASE = 5000


def load_corpus(vector: str | None = None) -> list[dict]:
    """The corpus, optionally narrowed to one attack surface.

    `vector` says *where* a record is planted: `ticket_note` records arrive as
    customer text through a tool result, `tool_description` records arrive as
    the server's own description of a tool. Different surface, different
    control -- the plan lock for the first, the pin check for the second.
    """
    records = [
        json.loads(line)
        for line in CORPUS.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if vector is None:
        return records
    return [r for r in records if r["vector"] == vector]


def ticket_for(index: int) -> str:
    return f"T-{CORPUS_TICKET_BASE + index}"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def seed_database(path: Path) -> Path:
    """A fresh database with every corpus record planted as a customer note."""
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


def drain(process: subprocess.Popen) -> str:
    try:
        out, _ = process.communicate(timeout=2)
    except subprocess.TimeoutExpired:  # pragma: no cover - defensive
        process.kill()
        out, _ = process.communicate()
    return (out or b"").decode("utf-8", "replace")[-4000:]


def wait_for(url: str, process: subprocess.Popen, timeout: float = 30.0) -> None:
    """Wait until the port answers, or fail with the server's own output.

    A 401 is the healthy answer: the server is up and refusing an
    unauthenticated request, which is the behaviour under test.
    """
    import httpx

    deadline = time.time() + timeout
    while time.time() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"server exited with {process.returncode}:\n{drain(process)}"
            )
        try:
            httpx.get(url, timeout=1.0)
            return
        except httpx.HTTPError:
            time.sleep(0.2)
    process.terminate()
    raise RuntimeError(f"{url} did not come up in {timeout}s:\n{drain(process)}")


@contextmanager
def running_servers(db_path: Path, audit_path: Path):
    """Reader and writer, in the server's own environment, over HTTP."""
    if not SERVER_PYTHON.exists():
        raise RuntimeError(
            f"{SERVER_PYTHON} is missing. The server resolves mcp 2.x in its own "
            "environment; run `uv sync --group dev` inside server/ first."
        )

    ports = {"reader": free_port(), "writer": free_port()}
    processes: dict[str, subprocess.Popen] = {}
    for role, port in ports.items():
        env = {
            **os.environ,
            "AIMAI_MCP_DB": str(db_path),
            "AIMAI_MCP_TOKENS": TOKENS,
            "AIMAI_MCP_AUDIT": str(audit_path),
            "AIMAI_MCP_AUDIT_SALT": "aimai-mcp-measurement",
            "AIMAI_MCP_ISSUER": f"http://127.0.0.1:{ports['reader']}",
            "AIMAI_MCP_WRITER_ISSUER": f"http://127.0.0.1:{ports['writer']}",
            "AIMAI_MCP_FETCH_ALLOWLIST": "status.example.com",
        }
        processes[role] = subprocess.Popen(
            [
                str(SERVER_PYTHON),
                "-m",
                "aimai_mcp_server",
                "--role",
                role,
                "--port",
                str(port),
                "--db",
                str(db_path),
            ],
            cwd=SERVER_DIR,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

    try:
        for role, port in ports.items():
            wait_for(f"http://127.0.0.1:{port}/mcp", processes[role])
        yield {
            "reader_url": f"http://127.0.0.1:{ports['reader']}/mcp",
            "writer_url": f"http://127.0.0.1:{ports['writer']}/mcp",
            "audit": audit_path,
            "db": db_path,
        }
    finally:
        for process in processes.values():
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:  # pragma: no cover - defensive
                process.kill()
