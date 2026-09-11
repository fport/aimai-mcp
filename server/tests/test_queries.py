"""The catalogue's two invariants, and what `bind` refuses."""

from __future__ import annotations

import pytest

from aimai_mcp_server import queries


@pytest.mark.parametrize("name", sorted(queries.QUERIES))
def test_every_query_filters_on_the_tenant(name):
    # Parametrized by name so a new query added without a tenant filter fails
    # as its own test rather than as one line inside someone else's.
    assert queries.tenant_filtered(queries.QUERIES[name]), (
        f"{name} does not constrain tenant_id = :tenant"
    )


@pytest.mark.parametrize("name", sorted(queries.QUERIES))
def test_no_query_accepts_a_tenant_parameter(name):
    declared = {p.name for p in queries.QUERIES[name].params}
    assert "tenant" not in declared
    assert not declared & {"tenant_id", "customer_scope", "role", "as_tenant"}


def test_bind_supplies_the_tenant_itself():
    _, bound = queries.bind("open_tickets", {}, "acme")
    assert bound == {"tenant": "acme"}


def test_bind_rejects_an_unknown_query():
    with pytest.raises(KeyError, match="list_queries"):
        queries.bind("select_everything", {}, "acme")


def test_bind_rejects_an_undeclared_argument():
    # Including the one that matters most: a caller trying to name its tenant.
    with pytest.raises(ValueError, match="does not take tenant"):
        queries.bind("open_tickets", {"tenant": "globex"}, "acme")


def test_bind_rejects_a_malformed_id():
    with pytest.raises(ValueError, match="does not match"):
        queries.bind("ticket_detail", {"ticket_id": "T-4001 OR 1=1"}, "acme")


def test_bind_requires_a_declared_parameter():
    with pytest.raises(ValueError, match="requires ticket_id"):
        queries.bind("ticket_detail", {}, "acme")


def test_catalogue_reports_the_untrusted_and_sensitive_flags():
    by_name = {q["name"]: q for q in queries.catalogue()}
    assert by_name["ticket_notes"]["returns_untrusted_text"] is True
    assert by_name["customer_directory"]["sensitive"] is True
    assert by_name["open_tickets"]["sensitive"] is False
