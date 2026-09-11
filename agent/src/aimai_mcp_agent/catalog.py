"""What each tool *is*, declared once and read by every gate.

Four questions get asked about a tool in this codebase -- which server serves
it, can it read secrets, can it take in attacker-controlled text, can it send
anything out, and is it undoable. Answering them in four different modules is
how they drift apart, so they are answered here and nowhere else.

The action class deserves its own note. The tempting axis is "how risky does
this feel", which produces an argument. The useful axis is **"is there a call
that puts the world back"** -- a question with a yes or no answer that two
engineers will agree on:

| class                  | example                 | undo                       |
|------------------------|-------------------------|----------------------------|
| READ                   | run_query               | nothing happened           |
| REVERSIBLE_WRITE       | update_ticket_status    | set the previous status    |
| IRREVERSIBLE           | refund_invoice, email   | none exists                |
| PRIVILEGE_ESCALATION   | grant_agent_access      | revocable, but widens who  |
|                        |                         | may act before you notice  |

`update_ticket_status` feels more dangerous than `send_customer_email` to
someone picturing a closed ticket. It is not: a status goes back with one
call, and a sent message never does.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ActionClass(StrEnum):
    READ = "read"
    REVERSIBLE_WRITE = "reversible_write"
    IRREVERSIBLE = "irreversible"
    PRIVILEGE_ESCALATION = "privilege_escalation"


class Capability(StrEnum):
    # Reads records the company would not publish: names, addresses, amounts.
    SENSITIVE_READ = "sensitive_read"
    # Brings text into the context that someone outside the company wrote.
    UNTRUSTED_INPUT = "untrusted_input"
    # Can carry bytes out of the building. A URL counts; no response needed.
    EXTERNAL_CHANNEL = "external_channel"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    server: str  # "reader" | "writer"
    action: ActionClass
    capabilities: frozenset[Capability]
    # A second, independent human. Only for actions that widen authority:
    # the person approving it is often the person who would benefit.
    second_signature: bool = False


def _spec(name, server, action, *caps, second_signature=False) -> ToolSpec:
    return ToolSpec(name, server, action, frozenset(caps), second_signature)


CATALOG: dict[str, ToolSpec] = {
    "list_queries": _spec("list_queries", "reader", ActionClass.READ),
    # Worst case, on purpose: the catalogue holds queries that return customer
    # records and queries that return customer-written notes, and the static
    # checks run before anyone knows which one a step will ask for.
    "run_query": _spec(
        "run_query",
        "reader",
        ActionClass.READ,
        Capability.SENSITIVE_READ,
        Capability.UNTRUSTED_INPUT,
    ),
    "fetch_url": _spec(
        "fetch_url",
        "reader",
        ActionClass.READ,
        Capability.UNTRUSTED_INPUT,
        Capability.EXTERNAL_CHANNEL,
    ),
    "update_ticket_status": _spec(
        "update_ticket_status", "writer", ActionClass.REVERSIBLE_WRITE
    ),
    # Irreversible, but not an exfiltration channel: it moves money, it does
    # not carry attacker-chosen bytes anywhere. Different axis, different gate.
    "refund_invoice": _spec("refund_invoice", "writer", ActionClass.IRREVERSIBLE),
    "grant_agent_access": _spec(
        "grant_agent_access",
        "writer",
        ActionClass.PRIVILEGE_ESCALATION,
        second_signature=True,
    ),
    "send_customer_email": _spec(
        "send_customer_email",
        "writer",
        ActionClass.IRREVERSIBLE,
        Capability.EXTERNAL_CHANNEL,
    ),
}

READ_ONLY_TOOLS = frozenset(
    name for name, spec in CATALOG.items() if spec.action is ActionClass.READ
)


def spec(name: str) -> ToolSpec:
    try:
        return CATALOG[name]
    except KeyError:
        raise KeyError(f"{name} is not a known tool") from None


def capabilities_of(tools: frozenset[str] | set[str]) -> frozenset[Capability]:
    caps: set[Capability] = set()
    for name in tools:
        if name in CATALOG:
            caps |= CATALOG[name].capabilities
    return frozenset(caps)


def server_of(name: str) -> str:
    return spec(name).server
