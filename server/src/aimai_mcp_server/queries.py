"""The query catalogue: named templates, never free SQL.

A tool that takes SQL takes the database's whole surface as its input schema,
and the only thing standing between a model and `DROP TABLE` is the model. The
catalogue inverts that: the tool argument is a *name*, the SQL is written here
by a human, and anything not in this dict does not exist as far as the wire is
concerned.

Two invariants hold for every entry and both are tested:

1.  the SQL filters on `tenant_id = :tenant`, and
2.  `:tenant` is never a declared parameter, so no caller can supply it.

The second one matters more than it looks. A template that filters correctly
but lets the caller name the tenant is not isolated, it is polite.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Matches `tenant_id = :tenant`, with or without a table alias, in any case.
TENANT_FILTER = re.compile(r"\b[\w.]*tenant_id\s*=\s*:tenant\b", re.IGNORECASE)


@dataclass(frozen=True)
class Param:
    """One declared query parameter.

    `pattern` is the whole validation story. The value reaches SQLite as a
    bound parameter either way, so this is not about injection -- it is about
    refusing a malformed id early, with a message that tells the model what
    the right shape was.
    """

    name: str
    description: str
    pattern: str
    required: bool = True

    def check(self, value: object) -> str:
        if not isinstance(value, str):
            raise ValueError(
                f"{self.name} must be a string, got {type(value).__name__}"
            )
        if not re.fullmatch(self.pattern, value):
            raise ValueError(
                f"{self.name}={value!r} does not match {self.pattern}; "
                "call list_queries for the accepted shape"
            )
        return value


@dataclass(frozen=True)
class Query:
    name: str
    description: str
    sql: str
    params: tuple[Param, ...] = ()
    # Rows that leave the company's own records: names, email addresses,
    # amounts. The trifecta check treats a call to one of these as the
    # "sensitive read" leg.
    sensitive: bool = False
    # Rows carrying text a customer wrote. The client wraps these before a
    # model reads them; the server flags them so the client does not have to
    # guess from the column name.
    untrusted: bool = False
    columns: tuple[str, ...] = field(default=())


QUERIES: dict[str, Query] = {
    "open_tickets": Query(
        name="open_tickets",
        description="Tickets that are not closed, newest first.",
        sql="""
            SELECT ticket_id, customer_id, subject, status, priority, opened_at
            FROM tickets
            WHERE tenant_id = :tenant AND status != 'closed'
            ORDER BY opened_at DESC
        """,
        columns=(
            "ticket_id",
            "customer_id",
            "subject",
            "status",
            "priority",
            "opened_at",
        ),
    ),
    "ticket_detail": Query(
        name="ticket_detail",
        description="One ticket with the customer's name and plan.",
        sql="""
            SELECT t.ticket_id, t.subject, t.status, t.priority, t.opened_at,
                   c.name AS customer_name, c.plan
            FROM tickets t
            JOIN customers c
              ON c.tenant_id = t.tenant_id AND c.customer_id = t.customer_id
            WHERE t.tenant_id = :tenant AND t.ticket_id = :ticket_id
        """,
        params=(Param("ticket_id", "Ticket identifier, e.g. T-4001", r"[A-Z]-\d{4}"),),
        sensitive=True,
        columns=(
            "ticket_id",
            "subject",
            "status",
            "priority",
            "opened_at",
            "customer_name",
            "plan",
        ),
    ),
    "ticket_notes": Query(
        name="ticket_notes",
        description=(
            "Notes on one ticket. Rows with from_customer=1 were written "
            "outside the company and are untrusted input."
        ),
        sql="""
            SELECT note_id, author, body, from_customer
            FROM ticket_notes
            WHERE tenant_id = :tenant AND ticket_id = :ticket_id
            ORDER BY note_id
        """,
        params=(Param("ticket_id", "Ticket identifier, e.g. T-4001", r"[A-Z]-\d{4}"),),
        untrusted=True,
        columns=("note_id", "author", "body", "from_customer"),
    ),
    "search_tickets": Query(
        name="search_tickets",
        description="Tickets whose subject contains a term.",
        sql="""
            SELECT ticket_id, subject, status, priority
            FROM tickets
            WHERE tenant_id = :tenant AND subject LIKE '%' || :term || '%'
            ORDER BY opened_at DESC
        """,
        params=(
            Param(
                "term",
                "Search term, letters/digits/spaces, 2-40 chars",
                r"[\w \-]{2,40}",
            ),
        ),
        columns=("ticket_id", "subject", "status", "priority"),
    ),
    "customer_directory": Query(
        name="customer_directory",
        description="Customers with their email addresses and plans.",
        sql="""
            SELECT customer_id, name, email, plan
            FROM customers
            WHERE tenant_id = :tenant
            ORDER BY customer_id
        """,
        sensitive=True,
        columns=("customer_id", "name", "email", "plan"),
    ),
    "overdue_invoices": Query(
        name="overdue_invoices",
        description="Unpaid invoices with amounts, oldest first.",
        sql="""
            SELECT invoice_id, customer_id, amount, issued_at
            FROM invoices
            WHERE tenant_id = :tenant AND status = 'overdue'
            ORDER BY issued_at
        """,
        sensitive=True,
        columns=("invoice_id", "customer_id", "amount", "issued_at"),
    ),
    "invoice_detail": Query(
        name="invoice_detail",
        description="One invoice with its amount and status.",
        sql="""
            SELECT invoice_id, customer_id, amount, status, issued_at
            FROM invoices
            WHERE tenant_id = :tenant AND invoice_id = :invoice_id
        """,
        params=(
            Param("invoice_id", "Invoice identifier, e.g. INV-7001", r"INV-\d{4}"),
        ),
        sensitive=True,
        columns=("invoice_id", "customer_id", "amount", "status", "issued_at"),
    ),
}


def tenant_filtered(query: Query) -> bool:
    """True when the template constrains the tenant and does not accept one."""
    if not TENANT_FILTER.search(query.sql):
        return False
    return all(p.name != "tenant" for p in query.params)


def bind(
    name: str, arguments: dict[str, object], tenant: str
) -> tuple[str, dict[str, object]]:
    """Resolve a named query into SQL and bound parameters.

    Raises `KeyError` for an unknown name and `ValueError` for a bad or extra
    argument. Extra arguments are an error rather than a shrug: silently
    dropping one is how a caller ends up believing it filtered something.
    """
    try:
        query = QUERIES[name]
    except KeyError:
        raise KeyError(
            f"unknown query {name!r}; call list_queries for the catalogue"
        ) from None

    declared = {p.name: p for p in query.params}
    unexpected = sorted(set(arguments) - set(declared))
    if unexpected:
        raise ValueError(
            f"query {name!r} does not take {', '.join(unexpected)}; "
            f"it takes {', '.join(declared) or 'no parameters'}"
        )

    bound: dict[str, object] = {"tenant": tenant}
    for param in query.params:
        if param.name not in arguments:
            if param.required:
                raise ValueError(f"query {name!r} requires {param.name}")
            continue
        bound[param.name] = param.check(arguments[param.name])
    return query.sql, bound


def catalogue() -> list[dict[str, object]]:
    """The catalogue as the `list_queries` tool returns it."""
    return [
        {
            "name": q.name,
            "description": q.description,
            "parameters": [
                {"name": p.name, "description": p.description, "pattern": p.pattern}
                for p in q.params
            ],
            "columns": list(q.columns),
            "sensitive": q.sensitive,
            "returns_untrusted_text": q.untrusted,
        }
        for q in QUERIES.values()
    ]
