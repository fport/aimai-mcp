"""Two tenants, one table: the result sets must not meet anywhere."""

from __future__ import annotations

import pytest

from aimai_mcp_server import queries
from aimai_mcp_server.store import WriteRefused

READ_ONLY_QUERIES = [n for n in sorted(queries.QUERIES)]


@pytest.mark.parametrize("name", READ_ONLY_QUERIES)
def test_no_query_returns_the_other_tenants_rows(reader, acme, globex, name):
    # Parametrized over the catalogue, so a query added later is covered the
    # moment it is added -- which is the only way this test stays true.
    args = _arguments_for(name)
    ours = reader.run_query(name, args["acme"], acme, limit=200)
    theirs = reader.run_query(name, args["globex"], globex, limit=200)
    ids = {_identity(r) for r in ours["rows"]}
    other = {_identity(r) for r in theirs["rows"]}
    # Both sides must actually return something, or "they do not intersect" is
    # a statement about two empty sets.
    assert ids and other, f"{name} returned nothing for one tenant"
    assert not (ids & other), f"{name} leaked rows across tenants"


def test_asking_for_the_other_tenants_ticket_returns_nothing(reader, acme):
    # T-9001 exists -- for globex. An acme token sees an empty result, not a
    # permission error, because "not found" and "not yours" are the same
    # answer when the alternative confirms the row exists.
    out = reader.run_query("ticket_detail", {"ticket_id": "T-9001"}, acme)
    assert out["rows"] == []


def test_a_write_cannot_reach_across_tenants(writer, acme):
    with pytest.raises(WriteRefused, match="not found"):
        writer.update_ticket_status("T-9001", "closed", acme)


def test_pagination_walks_without_repeating(reader, acme):
    first = reader.run_query("open_tickets", {}, acme, limit=1, offset=0)
    assert first["truncated"] is True
    second = reader.run_query(
        "open_tickets", {}, acme, limit=1, offset=first["next_offset"]
    )
    assert first["rows"][0]["ticket_id"] != second["rows"][0]["ticket_id"]


def _arguments_for(name: str) -> dict[str, dict]:
    """Per-tenant arguments for a query that needs one."""
    if name == "ticket_detail" or name == "ticket_notes":
        return {"acme": {"ticket_id": "T-4001"}, "globex": {"ticket_id": "T-9001"}}
    if name == "invoice_detail":
        return {
            "acme": {"invoice_id": "INV-7001"},
            "globex": {"invoice_id": "INV-8001"},
        }
    if name == "search_tickets":
        return {"acme": {"term": "re"}, "globex": {"term": "re"}}
    return {"acme": {}, "globex": {}}


def _identity(row: dict) -> tuple:
    for key in ("ticket_id", "invoice_id", "note_id", "customer_id"):
        if key in row:
            return (key, row[key])
    return tuple(sorted(row.items()))
