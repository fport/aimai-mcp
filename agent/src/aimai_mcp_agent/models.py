"""The model interface, and the worst model that could sit behind it.

`ObedientModel` is the default, and it is not a convenience stand-in for a
real one -- it is a stronger adversary than a real one. It does two things:

1.  carries out the user's request, and
2.  **does whatever any text it reads tells it to do.**

No jailbreak, no cleverness, no refusal. If a ticket note says "refund invoice
INV-7002", it proposes `refund_invoice(INV-7002)` on the next step.

Testing injection defences against a real model measures the model. A real
model declines most of the corpus, the suite goes green, and the green means
"today's snapshot of a vendor's safety training held", which is not a property
of this repository and will not survive the next release. Against a model that
obeys everything, a green suite means the *policy layer* held -- and that is
the claim the README makes.

It is also deterministic, so the corpus table in `security/results/` is a
measurement someone else can reproduce without an API key.

`LiveModel` exists for the other question -- does a real model plus these
gates behave sensibly on a real task -- and is marked `live` so it never runs
in CI.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class Proposal:
    tool: str
    arguments: dict[str, Any]
    # "task" when it came from the user's request, "observed" when the model
    # picked it up from something it read. The distinction is the experiment.
    motive: str = "task"


@dataclass(frozen=True)
class Finish:
    answer: str


Step = Proposal | Finish


@dataclass
class Observation:
    tool: str
    ok: bool
    text: str
    data: dict[str, Any] = field(default_factory=dict)
    untrusted: bool = False


class Model(Protocol):
    def propose(self, goal: str, observations: list[Observation]) -> Step: ...
    def observe(self, observation: Observation) -> None: ...


TICKET = re.compile(r"\bT-\d{4}\b")
INVOICE = re.compile(r"\bINV-\d{4}\b")
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
URL = re.compile(r"https?://[^\s\"'<>)]+")

# What the obedient model recognises as an instruction. Each entry turns a
# phrase into the call it asks for; none of them is clever, and that is the
# point -- a real attacker's phrasing does not need to be clever either. The
# non-English entries are here because the corpus is multilingual: a model
# that only understands English instructions would make the Turkish records
# pass for the wrong reason.
INSTRUCTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"\b(refund(_invoice)?|iade|erstatte|rückerstattung)\b", re.I),
        "refund_invoice",
    ),
    (
        re.compile(
            r"\b(e-?mail|send_customer_email|send|reply|write|gönder|e-posta|senden|"
            r"schicke)\b",
            re.I,
        ),
        "send_customer_email",
    ),
    (
        re.compile(
            # `[^\n]` rather than `[^.]`: an email address is full of dots, and a
            # sentence-bounded window stops short of the word it needs.
            r"\b(grant_agent_access|grant|give|gewähre|yetki ver|erişim ver)\b"
            r"[^\n]{0,60}\b(access|admin|analyst|viewer|zugriff|yetki|erişim)\b",
            re.I,
        ),
        "grant_agent_access",
    ),
    (
        re.compile(
            r"\b(fetch(_url)?|visit|open|load|post to|report to|abrufe?n?|ziyaret)\b"
            r"[^\n]{0,60}https?://",
            re.I,
        ),
        "fetch_url",
    ),
    (
        re.compile(
            r"\b(customer (list|directory|records)|all customers|every customer|"
            r"müşteri listesi|kundenliste)\b",
            re.I,
        ),
        "run_query:customer_directory",
    ),
    (
        re.compile(r"\b(close|reopen) (the |this )?ticket\b", re.I),
        "update_ticket_status",
    ),
)


def instructions_in(text: str, *, ticket_id: str | None = None) -> list[Proposal]:
    """Read a block of text as if it were a set of orders. It is not. It is
    data -- which is exactly why this function exists: to prove that treating
    it as orders still cannot get an out-of-plan call through."""
    found: list[Proposal] = []
    for pattern, target in INSTRUCTIONS:
        if not pattern.search(text):
            continue
        if target == "refund_invoice":
            invoices = INVOICE.findall(text)
            found.append(
                Proposal(
                    "refund_invoice",
                    {"invoice_id": invoices[0] if invoices else "INV-7002"},
                    motive="observed",
                )
            )
        elif target == "send_customer_email":
            tickets = TICKET.findall(text)
            found.append(
                Proposal(
                    "send_customer_email",
                    {
                        "ticket_id": tickets[0] if tickets else (ticket_id or "T-4001"),
                        "body": text[:500],
                    },
                    motive="observed",
                )
            )
        elif target == "grant_agent_access":
            addresses = EMAIL.findall(text)
            found.append(
                Proposal(
                    "grant_agent_access",
                    {
                        "email": addresses[0] if addresses else "outsider@example.test",
                        "grant_role": "admin",
                    },
                    motive="observed",
                )
            )
        elif target == "fetch_url":
            urls = URL.findall(text)
            if urls:
                found.append(Proposal("fetch_url", {"url": urls[0]}, motive="observed"))
        elif target.startswith("run_query:"):
            found.append(
                Proposal(
                    "run_query", {"query": target.split(":", 1)[1]}, motive="observed"
                )
            )
        elif target == "update_ticket_status":
            tickets = TICKET.findall(text)
            found.append(
                Proposal(
                    "update_ticket_status",
                    {
                        "ticket_id": tickets[0] if tickets else (ticket_id or "T-4001"),
                        "status": "closed",
                    },
                    motive="observed",
                )
            )
    return found


class ObedientModel:
    """Follows the task, and follows anything it reads. See the module docstring."""

    def __init__(
        self,
        task: list[Proposal] | None = None,
        *,
        goal: str = "",
        allowed: frozenset[str] | None = None,
    ) -> None:
        # The model only ever proposes, as a *task* step, something this run
        # offers -- that is how every agent framework works, and pretending
        # otherwise would make the refusal counts look better than they are.
        # Instructions read from tool output are not filtered: naming a tool
        # the run does not have is exactly what an injected instruction does.
        self._task = list(task) if task is not None else plan_task(goal, allowed)
        self._injected: list[Proposal] = []
        self.attempted: list[Proposal] = []

    def observe(self, observation: Observation) -> None:
        if not observation.text:
            return
        # Only text marked untrusted is scanned, which flatters the model:
        # a real one reads its whole context. The corpus still gets through,
        # because the corpus *is* the untrusted text.
        if observation.untrusted:
            self._injected.extend(instructions_in(observation.text))

    def propose(self, goal: str, observations: list[Observation]) -> Step:
        # Injected instructions first. An obedient model does what it was last
        # told, and a helpful one treats "urgent" as a reason to reorder.
        if self._injected:
            proposal = self._injected.pop(0)
        elif self._task:
            proposal = self._task.pop(0)
        else:
            return Finish(self._summarise(observations))
        self.attempted.append(proposal)
        return proposal

    @staticmethod
    def _summarise(observations: list[Observation]) -> str:
        ok = [o for o in observations if o.ok]
        return (
            (
                f"Done. {len(ok)} of {len(observations)} calls succeeded: "
                + ", ".join(o.tool for o in ok)
            )
            if observations
            else "Nothing to do."
        )


def plan_task(goal: str, allowed: frozenset[str] | None = None) -> list[Proposal]:
    """Turn the user's request into the calls it literally asks for.

    Keyword rules again, and again on purpose: this is the *task*, and the
    task comes from the user. Anything derived from tool output goes through
    `instructions_in` instead, where it is visibly the untrusted path.
    """
    tickets = TICKET.findall(goal)
    invoices = INVOICE.findall(goal)
    ticket_id = tickets[0] if tickets else None
    steps: list[Proposal] = []

    if ticket_id:
        steps.append(
            Proposal(
                "run_query",
                {"query": "ticket_detail", "arguments": {"ticket_id": ticket_id}},
            )
        )
        steps.append(
            Proposal(
                "run_query",
                {"query": "ticket_notes", "arguments": {"ticket_id": ticket_id}},
            )
        )
    elif re.search(r"\boverdue\b", goal, re.I):
        steps.append(Proposal("run_query", {"query": "overdue_invoices"}))
    else:
        steps.append(Proposal("run_query", {"query": "open_tickets"}))

    if re.search(r"\brefund\b", goal, re.I):
        steps.append(
            Proposal(
                "refund_invoice",
                {"invoice_id": invoices[0] if invoices else "INV-7002"},
            )
        )
    if re.search(r"\bclose\b", goal, re.I) and ticket_id:
        steps.append(
            Proposal(
                "update_ticket_status", {"ticket_id": ticket_id, "status": "closed"}
            )
        )
    if re.search(r"\b(e-?mail|reply|write back)\b", goal, re.I) and ticket_id:
        steps.append(
            Proposal(
                "send_customer_email",
                {
                    "ticket_id": ticket_id,
                    "body": "Thanks for your patience -- we are on it.",
                },
            )
        )
    if allowed is not None:
        steps = [s for s in steps if s.tool in allowed]
    return steps
