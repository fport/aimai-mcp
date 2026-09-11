"""Who has to say yes, and how long they took saying it.

The classification lives in `catalog.py`; this module turns it into a gate and
a record. Three rules:

* **READ and REVERSIBLE_WRITE run on their own**, the second with an audit
  entry. Stopping a human for something that undoes with one call trains them
  to click approve, and an approval queue nobody reads is worse than none.
* **IRREVERSIBLE stops.** One human, one decision, with the arguments in front
  of them.
* **PRIVILEGE_ESCALATION stops and needs two**, from different people. The
  person approving "give this address admin" is often the person who benefits;
  a second signature is the cheapest control against that, and it is the one
  place in this repo where a rule is about the approver rather than the agent.

Every request and decision is timestamped, because "approval queue p50/p95"
and "approve / reject ratio" are the two numbers that say whether the gate is
working or merely present. A queue with a p95 of two days does not protect
anything -- it gets routed around.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from .catalog import ActionClass, spec

AUTOMATIC = frozenset({ActionClass.READ, ActionClass.REVERSIBLE_WRITE})


def classify(tool: str) -> ActionClass:
    return spec(tool).action


def requires_approval(tool: str) -> bool:
    return classify(tool) not in AUTOMATIC


def signatures_required(tool: str) -> int:
    return 2 if spec(tool).second_signature else 1


@dataclass(frozen=True)
class ApprovalRequest:
    id: str
    tool: str
    arguments: dict[str, Any]
    action: ActionClass
    signatures_required: int
    goal: str
    requested_at: float

    def summary(self) -> str:
        args = ", ".join(f"{k}={v!r}" for k, v in sorted(self.arguments.items()))
        return (
            f"[{self.action.value}] {self.tool}({args})\n"
            f"  for: {self.goal}\n"
            f"  signatures required: {self.signatures_required}"
        )


@dataclass
class ApprovalOutcome:
    request: ApprovalRequest
    approved: bool
    signatures: list[str] = field(default_factory=list)
    reason: str = ""
    decided_at: float = 0.0

    @property
    def waited_seconds(self) -> float:
        return max(0.0, self.decided_at - self.request.requested_at)


class Approver(Protocol):
    """Returns `(approved, signer_identity, reason)` for one signature."""

    def __call__(
        self, request: ApprovalRequest, signature_index: int
    ) -> tuple[bool, str, str]: ...


def deny_all(request: ApprovalRequest, signature_index: int) -> tuple[bool, str, str]:
    """The default in tests and in any unattended run.

    An agent that cannot reach a human does not get to decide that the human
    would have said yes.
    """
    return False, "", "no approver is attached to this run"


def approve_all(
    request: ApprovalRequest, signature_index: int
) -> tuple[bool, str, str]:
    """For demos and measurement runs only. Never a production default."""
    return True, f"auto-{signature_index}", "auto-approved"


def cli_approver(reader: Callable[[str], str] = input) -> Approver:
    """Prompts a person on the terminal. One prompt per signature."""

    def ask(request: ApprovalRequest, signature_index: int) -> tuple[bool, str, str]:
        print(
            f"\nApproval {signature_index + 1}/{request.signatures_required} required:"
        )
        print(request.summary())
        answer = reader("approve? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            return False, "", "declined at the prompt"
        who = reader("your name: ").strip() or "unnamed"
        return True, who, ""

    return ask


class ApprovalGate:
    """Runs the required number of signatures and keeps the record."""

    def __init__(self, approver: Approver = deny_all) -> None:
        self.approver = approver
        self.outcomes: list[ApprovalOutcome] = []

    def request(
        self, tool: str, arguments: dict[str, Any], goal: str
    ) -> ApprovalOutcome:
        action = classify(tool)
        needed = signatures_required(tool)
        req = ApprovalRequest(
            id=uuid.uuid4().hex[:8],
            tool=tool,
            arguments=dict(arguments),
            action=action,
            signatures_required=needed,
            goal=goal,
            requested_at=time.time(),
        )

        signatures: list[str] = []
        approved, reason = True, ""
        for index in range(needed):
            ok, who, why = self.approver(req, index)
            if not ok:
                approved, reason = False, why or "declined"
                break
            # Two signatures from the same person is one signature typed
            # twice, which is exactly what the rule exists to prevent.
            if who in signatures:
                approved, reason = False, f"{who} already signed this request"
                break
            signatures.append(who)

        outcome = ApprovalOutcome(
            request=req,
            approved=approved and len(signatures) == needed,
            signatures=signatures,
            reason=reason,
            decided_at=time.time(),
        )
        self.outcomes.append(outcome)
        return outcome

    def waits(self) -> list[float]:
        return [o.waited_seconds for o in self.outcomes]

    def approval_rate(self) -> float | None:
        if not self.outcomes:
            return None
        return sum(1 for o in self.outcomes if o.approved) / len(self.outcomes)
