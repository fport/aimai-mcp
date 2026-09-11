"""The plan lock: what this run may do, decided before it reads anything.

This is the load-bearing control in the repo, and it is worth being precise
about why. Wrapping untrusted text and running a detector over it are both
useful and neither is a guarantee -- one is a hint to the model, the other is
a classifier with a false-negative rate. The guarantee comes from *when* the
permission set is fixed:

    build_plan(request)   <- the only input is what the user asked for
    trifecta_check(plan)  <- refuse or split, before any I/O
    ... read untrusted text ...
    authorize(...)        <- checks against a set that can no longer change

Text read at step 4 cannot widen a set frozen at step 1. Not because the model
is careful, but because `allowed` is a `frozenset` on a frozen dataclass and
nothing in the run has a reference that could rebind it.

The rules below are deliberately dull keyword matching. An LLM deciding the
permission set would put the permission set back under the influence of text,
which is the thing being defended against.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace

from .catalog import CATALOG, READ_ONLY_TOOLS
from .trifecta import split_for_trifecta, trifecta_check

# Always available: naming the catalogue is how a step finds out what exists.
BASE_TOOLS = frozenset({"list_queries", "run_query"})

# Locking the tool set alone leaves a gap, and it is worth naming: `run_query`
# is one tool with seven different blast radii behind it. A run allowed to
# read open tickets and steered into reading the customer directory has not
# called an out-of-plan *tool*, and an injected instruction is perfectly
# capable of doing the steering. So the plan locks query names too.
BASE_QUERIES = frozenset({"open_tickets", "search_tickets"})

MAX_STEPS = 8

# Intent -> the extra tools that intent justifies. A request that does not
# ask for a side effect does not get the tools for one.
INTENTS: tuple[tuple[str, frozenset[str]], ...] = (
    (
        r"\b(close|reopen|re-open|set (the )?status"
        r"|move (it )?to (open|pending|closed))\b",
        frozenset({"update_ticket_status"}),
    ),
    (r"\b(refund|charge ?back|money back|reimburse)\b", frozenset({"refund_invoice"})),
    (
        r"\b(email|e-mail|reply to|write back|notify the customer)\b",
        frozenset({"send_customer_email"}),
    ),
    (
        r"\b(grant|give .* access|add .* as an? (viewer|analyst|admin))\b",
        frozenset({"grant_agent_access"}),
    ),
    (
        r"\b(status page|fetch|check the (docs|status)|look up online)\b",
        frozenset({"fetch_url"}),
    ),
)

# Same shape, one level down: which named queries this request justifies.
QUERY_INTENTS: tuple[tuple[str, frozenset[str]], ...] = (
    (
        r"\b[A-Z]-\d{4}\b|\bnotes?\b|\bticket\b",
        frozenset({"ticket_detail", "ticket_notes"}),
    ),
    (
        r"\b(invoice|refund|overdue|charge|billing|INV-\d{4})\b",
        frozenset({"invoice_detail", "overdue_invoices"}),
    ),
    (
        r"\b(customer (list|directory|records|emails?)|all customers"
        r"|contact details)\b",
        frozenset({"customer_directory"}),
    ),
)


class PlanLocked(RuntimeError):
    """Raised by any attempt to widen a plan after it was built."""


@dataclass(frozen=True)
class Plan:
    goal: str
    allowed: frozenset[str]
    allowed_queries: frozenset[str] = BASE_QUERIES
    max_steps: int = MAX_STEPS
    # Set when this plan is one leg of a split run.
    leg: int = 0
    of_legs: int = 1
    matched_intents: tuple[str, ...] = field(default=())

    def __post_init__(self) -> None:
        unknown = sorted(set(self.allowed) - set(CATALOG))
        if unknown:
            raise ValueError(f"plan allows unknown tools: {', '.join(unknown)}")

    def permits(self, tool: str) -> bool:
        return tool in self.allowed

    def permits_query(self, query: str) -> bool:
        return query in self.allowed_queries

    def widen(self, *tools: str) -> Plan:
        """There is no widening. The method exists so the refusal is findable.

        Without it, code that tries reaches `dataclasses.replace` or mutates a
        set, and the failure is an AttributeError somewhere unhelpful instead
        of a sentence explaining the rule.
        """
        raise PlanLocked(
            f"a plan cannot be widened after it is built (tried to add "
            f"{', '.join(tools)}). Start a new run with a new request."
        )

    def read_only(self) -> Plan:
        return replace(self, allowed=frozenset(self.allowed & READ_ONLY_TOOLS))


def build_plan(request: str, *, max_steps: int = MAX_STEPS) -> Plan:
    """Derive the permission set from the user's request and nothing else.

    Note what is *not* an input: the ticket contents, previous tool results,
    the model's opinion about what it will need. Those all arrive later, and
    later is after the lock.
    """
    text = request.lower()
    allowed = set(BASE_TOOLS)
    matched: list[str] = []
    for pattern, tools in INTENTS:
        if re.search(pattern, text):
            allowed |= set(tools)
            matched.append(pattern)

    queries = set(BASE_QUERIES)
    for pattern, names in QUERY_INTENTS:
        if re.search(pattern, request, re.IGNORECASE):
            queries |= set(names)

    return Plan(
        goal=request.strip(),
        allowed=frozenset(allowed),
        allowed_queries=frozenset(queries),
        max_steps=max_steps,
        matched_intents=tuple(matched),
    )


def plan_legs(plan: Plan) -> tuple[Plan, ...]:
    """One plan in, one or more trifecta-safe plans out.

    A request like "read the notes on T-4002 and email the customer" is a
    trifecta on its own, and refusing it outright would be honest but useless:
    it is a reasonable thing to ask for. Splitting it is the real answer --
    the reading leg has no way out, the sending leg never sees the notes, and
    what crosses between them is a structured hand-off rather than prose.
    """
    legs = split_for_trifecta(plan.allowed)
    if len(legs) == 1:
        trifecta_check(plan.allowed)
        return (plan,)
    # The sending leg gets no read tools at all. That is the point of the
    # cut: it acts on the hand-off it was given, and has nothing to exfiltrate
    # because it never read anything.
    return tuple(
        replace(plan, allowed=frozenset(tools), leg=index + 1, of_legs=len(legs))
        for index, tools in enumerate(legs)
    )
