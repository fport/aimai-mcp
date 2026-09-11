"""The plan lock: built from the request, frozen afterwards."""

from __future__ import annotations

import dataclasses

import pytest

from aimai_mcp_agent.plan import BASE_TOOLS, PlanLocked, build_plan, plan_legs
from aimai_mcp_agent.trifecta import TrifectaViolation, trifecta_check


def test_a_plain_question_gets_read_tools_only():
    plan = build_plan("What is open on T-4001?")
    assert plan.allowed == BASE_TOOLS


def test_asking_for_a_refund_is_what_grants_the_refund_tool():
    plan = build_plan("Refund the duplicate charge on INV-7002")
    assert "refund_invoice" in plan.allowed


def test_not_asking_for_it_is_what_withholds_it():
    plan = build_plan("Summarise the notes on T-4002")
    assert "refund_invoice" not in plan.allowed
    assert "send_customer_email" not in plan.allowed


def test_the_allowed_set_cannot_be_mutated():
    plan = build_plan("Summarise T-4001")
    assert isinstance(plan.allowed, frozenset)
    with pytest.raises(AttributeError):
        plan.allowed.add("refund_invoice")  # type: ignore[attr-defined]


def test_the_plan_object_cannot_be_rebound():
    plan = build_plan("Summarise T-4001")
    with pytest.raises(dataclasses.FrozenInstanceError):
        plan.allowed = frozenset({"refund_invoice"})  # type: ignore[misc]


def test_widening_raises_with_the_rule_in_the_message():
    plan = build_plan("Summarise T-4001")
    with pytest.raises(PlanLocked, match="cannot be widened"):
        plan.widen("refund_invoice")


def test_a_plan_cannot_name_a_tool_that_does_not_exist():
    from aimai_mcp_agent.plan import Plan

    with pytest.raises(ValueError, match="unknown tools"):
        Plan(goal="x", allowed=frozenset({"drop_database"}))


def test_a_read_and_send_request_is_split_rather_than_refused():
    # The request is reasonable; the toolset it implies is not. Splitting is
    # the answer, and the sending leg ends up with no read tools at all.
    plan = build_plan("Read the notes on T-4002 and email the customer")
    legs = plan_legs(plan)
    assert len(legs) == 2
    assert "send_customer_email" not in legs[0].allowed
    assert not (legs[1].allowed & BASE_TOOLS)
    for leg in legs:
        trifecta_check(leg.allowed)


def test_a_safe_request_is_one_leg():
    legs = plan_legs(build_plan("Close ticket T-4003"))
    assert len(legs) == 1
    assert legs[0].of_legs == 1


def test_the_trifecta_check_names_all_three_legs():
    with pytest.raises(TrifectaViolation) as excinfo:
        trifecta_check({"run_query", "send_customer_email"})
    message = str(excinfo.value)
    for leg in ("sensitive_read", "untrusted_input", "external_channel"):
        assert leg in message
    assert "Split the run" in message
