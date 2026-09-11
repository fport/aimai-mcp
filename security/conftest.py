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

import sys
from pathlib import Path

import pytest
from harness import (  # noqa: F401 - re-exported for the test modules
    SERVER_PYTHON,
    load_corpus,
    running_servers,
    seed_database,
    ticket_for,
)

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def seeded_db(tmp_path_factory) -> Path:
    if not SERVER_PYTHON.exists():
        pytest.skip(f"{SERVER_PYTHON} is missing; run `uv sync --group dev` in server/")
    return seed_database(tmp_path_factory.mktemp("db") / "support.sqlite3")


@pytest.fixture(scope="session")
def servers(seeded_db, tmp_path_factory):
    audit = tmp_path_factory.mktemp("audit") / "audit.jsonl"
    with running_servers(seeded_db, audit) as running:
        yield running


@pytest.fixture
def pins_path() -> Path:
    return ROOT / "agent" / "pins.json"


def pytest_report_header(config):  # pragma: no cover - reporting only
    return (
        f"security: client mcp in {sys.executable}, "
        f"server mcp in {SERVER_PYTHON if SERVER_PYTHON.exists() else 'MISSING'}"
    )
