"""No tool may accept an identity. This is the multi-tenancy guarantee.

Every other control here is a policy someone could relax. This one is a shape:
if `run_query(tenant=...)` does not type-check, no amount of persuasion in a
ticket note makes it exist. The test walks the live tool schemas rather than
the source, so a tool added through any path is covered.
"""

from __future__ import annotations

import pytest

from aimai_mcp_server.server import build_server

FORBIDDEN = {
    "tenant",
    "tenant_id",
    "org",
    "org_id",
    "account",
    "account_id",
    "customer_scope",
    "role",
    "as_role",
    "as_tenant",
    "user",
    "user_id",
    "principal",
    "token",
    "api_key",
    "authorization",
    "impersonate",
}


@pytest.fixture(params=["reader", "writer"])
async def tools(request, support_db):
    mcp, _, _ = build_server(request.param, db_path=support_db)
    return await mcp.list_tools()


async def test_no_tool_accepts_an_identity_argument(tools):
    offenders = []
    for tool in tools:
        # `input_schema` on the SDK object; `inputSchema` on the wire.
        properties = (tool.input_schema or {}).get("properties", {}) or {}
        for name in properties:
            if name.lower() in FORBIDDEN:
                offenders.append(f"{tool.name}.{name}")
    assert not offenders, f"identity arguments on the wire: {', '.join(offenders)}"


async def test_every_tool_documents_itself(tools):
    # The description is part of the fingerprint the client pins, and it is
    # the only thing a model reads before choosing. An undocumented tool is
    # both an unpinnable one and a guess.
    for tool in tools:
        assert tool.description and len(tool.description.strip()) > 40, tool.name


async def test_the_two_servers_expose_disjoint_tools(support_db):
    reader, _, _ = build_server("reader", db_path=support_db)
    writer, _, _ = build_server("writer", db_path=support_db)
    read_names = {t.name for t in await reader.list_tools()}
    write_names = {t.name for t in await writer.list_tools()}
    assert read_names and write_names
    assert not (read_names & write_names)
