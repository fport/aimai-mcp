"""Default deny, in the order the gates are meant to fire."""

from __future__ import annotations

import pytest

from aimai_mcp_agent.catalog import CATALOG
from aimai_mcp_agent.plan import Plan, build_plan
from aimai_mcp_agent.policy import POLICY, authorize

FULL = Plan(goal="test", allowed=frozenset(CATALOG))


def test_every_tool_has_a_policy_entry():
    # A tool with no entry is refused by default, which is correct and also
    # invisible. This test makes adding a tool a decision, not an omission.
    assert set(POLICY) == set(CATALOG)


def test_an_unknown_tool_is_refused():
    decision = authorize("admin", "drop_database", {}, FULL)
    assert not decision
    assert decision.denied_by == "unknown_tool"


def test_the_plan_is_checked_before_the_role():
    # An admin proposing a refund on a run that is not about refunds is
    # refused for the same reason a viewer would be: it is not this run.
    plan = build_plan("Summarise ticket T-4001")
    decision = authorize("admin", "refund_invoice", {"invoice_id": "INV-7002"}, plan)
    assert decision.denied_by == "plan"


def test_a_plan_refusal_says_why_and_what_is_allowed():
    plan = build_plan("Summarise ticket T-4001")
    decision = authorize("admin", "refund_invoice", {"invoice_id": "INV-7002"}, plan)
    assert "not part of this run" in decision.reason
    assert "list_queries" in decision.reason
    assert "cannot add to that set" in decision.reason


def test_the_role_is_checked_once_the_plan_allows_it():
    plan = build_plan("Refund INV-7002")
    assert (
        authorize(
            "analyst", "refund_invoice", {"invoice_id": "INV-7002"}, plan
        ).denied_by
        == "role"
    )
    assert authorize("admin", "refund_invoice", {"invoice_id": "INV-7002"}, plan)


@pytest.mark.parametrize(
    "limit,ok", [(200, True), (201, False), (0, False), (True, False)]
)
def test_the_limit_constraint(limit, ok):
    plan = build_plan("List open tickets")
    decision = authorize(
        "analyst", "run_query", {"query": "open_tickets", "limit": limit}, plan
    )
    assert bool(decision) is ok
    if not ok:
        assert decision.denied_by == "constraint"


def test_an_agent_may_not_grant_the_role_that_grants_roles():
    plan = build_plan("Grant nadia@acme-supply.example admin access")
    decision = authorize(
        "admin",
        "grant_agent_access",
        {"email": "nadia@acme-supply.example", "grant_role": "admin"},
        plan,
    )
    assert decision.denied_by == "constraint"
    assert "not delegated to an agent" in decision.reason


def test_an_empty_email_body_is_refused():
    plan = build_plan("Email the customer on T-4001")
    decision = authorize(
        "analyst", "send_customer_email", {"ticket_id": "T-4001", "body": "  "}, plan
    )
    assert decision.denied_by == "constraint"


def test_a_viewer_cannot_reach_the_network():
    plan = build_plan("Check the status page")
    assert (
        authorize(
            "viewer", "fetch_url", {"url": "https://status.example.com"}, plan
        ).denied_by
        == "role"
    )
