"""Reversibility decides who has to say yes."""

from __future__ import annotations

import pytest

from aimai_mcp_agent.approval import (
    ApprovalGate,
    approve_all,
    classify,
    deny_all,
    requires_approval,
    signatures_required,
)
from aimai_mcp_agent.catalog import ActionClass


@pytest.mark.parametrize(
    "tool,action",
    [
        ("run_query", ActionClass.READ),
        ("update_ticket_status", ActionClass.REVERSIBLE_WRITE),
        ("refund_invoice", ActionClass.IRREVERSIBLE),
        ("send_customer_email", ActionClass.IRREVERSIBLE),
        ("grant_agent_access", ActionClass.PRIVILEGE_ESCALATION),
    ],
)
def test_the_classification(tool, action):
    assert classify(tool) is action


def test_a_reversible_write_does_not_stop_a_human():
    # It feels riskier than sending an email. It is not: one call puts the
    # status back, and nothing puts a sent message back.
    assert not requires_approval("update_ticket_status")
    assert requires_approval("send_customer_email")


def test_privilege_escalation_needs_two_signatures():
    assert signatures_required("grant_agent_access") == 2
    assert signatures_required("refund_invoice") == 1


def test_the_default_is_refusal():
    gate = ApprovalGate()
    outcome = gate.request("refund_invoice", {"invoice_id": "INV-7002"}, "test")
    assert not outcome.approved
    assert "no approver" in outcome.reason


def test_one_person_cannot_sign_twice():
    def same_person(request, index):
        return True, "nadia", ""

    gate = ApprovalGate(same_person)
    outcome = gate.request("grant_agent_access", {"email": "x@y.z"}, "test")
    assert not outcome.approved
    assert "already signed" in outcome.reason


def test_two_people_can():
    def two(request, index):
        return True, ["nadia", "kenji"][index], ""

    gate = ApprovalGate(two)
    outcome = gate.request("grant_agent_access", {"email": "x@y.z"}, "test")
    assert outcome.approved
    assert outcome.signatures == ["nadia", "kenji"]


def test_the_gate_records_what_it_needs_to_be_measured():
    gate = ApprovalGate(approve_all)
    gate.request("refund_invoice", {"invoice_id": "INV-7002"}, "test")
    gate.approver = deny_all
    gate.request("refund_invoice", {"invoice_id": "INV-7004"}, "test")

    assert gate.approval_rate() == 0.5
    assert len(gate.waits()) == 2
    assert all(w >= 0 for w in gate.waits())


def test_the_request_summary_shows_the_arguments_a_human_is_approving():
    gate = ApprovalGate(deny_all)
    outcome = gate.request(
        "refund_invoice", {"invoice_id": "INV-7002"}, "refund the duplicate"
    )
    summary = outcome.request.summary()
    assert "INV-7002" in summary and "irreversible" in summary
