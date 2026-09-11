"""Two tenants, over the wire, through the same tools.

The store-level version of this lives in `server/tests`. This one is the
statement that matters operationally: with two real tokens against a running
server, no query returns a row belonging to the other tenant, and there is no
argument that would make it.
"""

from __future__ import annotations

import pytest

from aimai_mcp_agent.client import ToolGateway

ACME = "tok-acme-analyst"
GLOBEX = "tok-globex-analyst"

QUERIES = [
    ("open_tickets", {}),
    ("customer_directory", {}),
    ("overdue_invoices", {}),
]


async def _rows(servers, pins_path, token, query, arguments):
    async with ToolGateway(
        reader_url=servers["reader_url"],
        writer_url=servers["writer_url"],
        token=token,
        pins_path=pins_path,
    ) as gateway:
        outcome = await gateway.call(
            "run_query", {"query": query, "arguments": arguments, "limit": 200}
        )
        assert outcome.ok, outcome.error
        return outcome.data["rows"]


@pytest.mark.parametrize("query,arguments", QUERIES, ids=[q for q, _ in QUERIES])
async def test_the_two_result_sets_never_intersect(
    servers, pins_path, query, arguments
):
    ours = await _rows(servers, pins_path, ACME, query, arguments)
    theirs = await _rows(servers, pins_path, GLOBEX, query, arguments)
    assert ours and theirs, "one tenant returned nothing; the comparison is empty"
    assert not ({_key(r) for r in ours} & {_key(r) for r in theirs})


async def test_a_token_cannot_ask_for_another_tenants_record(servers, pins_path):
    # T-9001 belongs to globex. An acme token gets an empty result rather than
    # a permission error: telling it apart would confirm the row exists.
    rows = await _rows(
        servers, pins_path, ACME, "ticket_detail", {"ticket_id": "T-9001"}
    )
    assert rows == []


async def test_there_is_no_argument_that_names_a_tenant(servers, pins_path):
    async with ToolGateway(
        reader_url=servers["reader_url"],
        writer_url=servers["writer_url"],
        token=ACME,
        pins_path=pins_path,
    ) as gateway:
        for tool in gateway.visible_tools:
            properties = set((tool.schema or {}).get("properties", {}))
            assert not properties & {"tenant", "tenant_id", "org", "account", "role"}


async def test_passing_one_anyway_is_refused_rather_than_ignored(servers, pins_path):
    # An argument the server drops silently is how a caller ends up believing
    # it filtered something.
    async with ToolGateway(
        reader_url=servers["reader_url"],
        writer_url=servers["writer_url"],
        token=ACME,
        pins_path=pins_path,
    ) as gateway:
        outcome = await gateway.call(
            "run_query", {"query": "open_tickets", "arguments": {"tenant": "globex"}}
        )
    assert not outcome.ok
    assert "does not take tenant" in outcome.error


async def test_a_reader_scoped_token_cannot_reach_the_writer(servers, pins_path):
    # Refused at the token check, before any policy runs and before the writer
    # learns anything about the caller.
    with pytest.raises(Exception) as excinfo:
        async with ToolGateway(
            reader_url=servers["reader_url"],
            writer_url=servers["writer_url"],
            token="tok-acme-readonly",
            pins_path=pins_path,
        ):
            pass
    assert excinfo.value is not None


async def test_the_same_token_still_opens_the_reader(servers, pins_path):
    async with ToolGateway(
        reader_url=servers["reader_url"],
        writer_url=None,
        token="tok-acme-readonly",
        pins_path=pins_path,
        strict_pins=False,
    ) as gateway:
        assert "run_query" in gateway.visible_names


def _key(row: dict) -> tuple:
    for field in ("ticket_id", "invoice_id", "customer_id"):
        if field in row:
            return (field, row[field])
    return tuple(sorted(row.items()))
