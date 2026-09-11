from __future__ import annotations

import pytest

from aimai_mcp_server import db
from aimai_mcp_server.auth import Principal
from aimai_mcp_server.store import SupportStore


@pytest.fixture
def support_db(tmp_path):
    return db.seed(tmp_path / "support.sqlite3")


@pytest.fixture
def reader(support_db):
    return SupportStore(support_db, readonly=True)


@pytest.fixture
def writer(support_db):
    return SupportStore(support_db, readonly=False)


@pytest.fixture
def acme():
    return Principal(tenant="acme", role="analyst")


@pytest.fixture
def globex():
    return Principal(tenant="globex", role="analyst")
