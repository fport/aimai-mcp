"""The reader's handle is refused by the engine, not by a convention."""

from __future__ import annotations

import sqlite3

import pytest

from aimai_mcp_server import db
from aimai_mcp_server.store import WriteRefused


def test_the_reader_cannot_write_even_in_raw_sql(support_db):
    conn = db.connect(support_db, readonly=True)
    try:
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            conn.execute(
                "INSERT INTO outbox (tenant_id, channel, target, body, sent_at)"
                " VALUES ('acme','email','x','y','z')"
            )
    finally:
        conn.close()


def test_the_writer_can(support_db):
    conn = db.connect(support_db, readonly=False)
    try:
        conn.execute(
            "INSERT INTO outbox (tenant_id, channel, target, body, sent_at)"
            " VALUES ('acme','email','x','y','z')"
        )
        conn.commit()
        assert conn.execute("SELECT COUNT(*) c FROM outbox").fetchone()["c"] == 1
    finally:
        conn.close()


def test_the_read_only_store_refuses_before_it_reaches_sqlite(reader, acme):
    # Two lines of defence, and this is the outer one: the store knows it is
    # read-only and says so with a message, rather than letting the engine
    # raise something about a database file.
    with pytest.raises(WriteRefused, match="read-only"):
        reader.update_ticket_status("T-4001", "closed", acme)
