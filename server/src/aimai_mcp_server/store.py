"""Everything that touches the database, with the tenant always supplied here.

The store takes a `Principal`, never a tenant argument from the wire. That is
the whole point of the layer: a tool handler cannot pass a tenant it did not
get from the token, because the signature does not let it.

Writes live here too, and each one returns the compensating call that undoes
it -- or says there is none. "Reversible" is not a vibe about how scary an
action feels; it is a question with a yes/no answer: is there a call that puts
the world back? `undo` carries that answer to the approval gate.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import db, queries
from .auth import Principal
from .limits import LIMITS, Limits, clamp_page, shape_result

TICKET_STATUSES = ("open", "pending", "closed")
ACCESS_ROLES = ("viewer", "analyst", "admin")


class WriteRefused(RuntimeError):
    """A write the store itself will not perform, for reasons of its own."""


@dataclass(frozen=True)
class WriteResult:
    changed: bool
    detail: dict[str, Any]
    # The call that reverses this one, or None when nothing does.
    undo: dict[str, Any] | None


class SupportStore:
    def __init__(
        self,
        path: str | Path,
        *,
        readonly: bool,
        limits: Limits = LIMITS,
    ) -> None:
        self.path = Path(path)
        self.readonly = readonly
        self.limits = limits

    def _connect(self) -> sqlite3.Connection:
        return db.connect(self.path, readonly=self.readonly)

    # ---------------------------------------------------------------- reads

    def run_query(
        self,
        name: str,
        arguments: dict[str, Any],
        principal: Principal,
        *,
        limit: int | None = None,
        offset: int | None = None,
    ) -> dict[str, Any]:
        sql, bound = queries.bind(name, arguments, principal.tenant)
        page, start = clamp_page(limit, offset, self.limits)

        # One row past the page, so `had_more` is a fact rather than a guess
        # from a second COUNT query that could disagree under concurrency.
        paged = f"{sql}\nLIMIT :_limit OFFSET :_offset"
        bound = {**bound, "_limit": page + 1, "_offset": start}

        conn = self._connect()
        try:
            rows = [dict(r) for r in conn.execute(paged, bound).fetchall()]
        finally:
            conn.close()

        had_more = len(rows) > page
        result = shape_result(
            rows[:page], limit=page, offset=start, had_more=had_more, limits=self.limits
        )
        query = queries.QUERIES[name]
        result["query"] = name
        result["sensitive"] = query.sensitive
        result["returns_untrusted_text"] = query.untrusted
        return result

    def summary(self, principal: Principal) -> dict[str, Any]:
        """Counts for the tenant behind the token. Backs the resource."""
        conn = self._connect()
        try:
            row = conn.execute(
                """
                SELECT
                  (SELECT COUNT(*) FROM tickets
                    WHERE tenant_id = :tenant AND status != 'closed') AS open_tickets,
                  (SELECT COUNT(*) FROM tickets
                    WHERE tenant_id = :tenant AND priority IN ('high','urgent')
                      AND status != 'closed') AS urgent_tickets,
                  (SELECT COUNT(*) FROM invoices
                    WHERE tenant_id = :tenant AND status = 'overdue')
                      AS overdue_invoices,
                  (SELECT COUNT(*) FROM customers
                    WHERE tenant_id = :tenant) AS customers
                """,
                {"tenant": principal.tenant},
            ).fetchone()
        finally:
            conn.close()
        return {"tenant": principal.tenant, **dict(row)}

    def ticket_for_prompt(
        self, ticket_id: str, principal: Principal
    ) -> dict[str, Any] | None:
        conn = self._connect()
        try:
            row = conn.execute(
                """
                SELECT ticket_id, subject, status, priority
                FROM tickets WHERE tenant_id = :tenant AND ticket_id = :ticket_id
                """,
                {"tenant": principal.tenant, "ticket_id": ticket_id},
            ).fetchone()
        finally:
            conn.close()
        return dict(row) if row else None

    # --------------------------------------------------------------- writes

    def _require_writable(self) -> None:
        if self.readonly:
            raise WriteRefused("this server is read-only")

    def update_ticket_status(
        self, ticket_id: str, status: str, principal: Principal
    ) -> WriteResult:
        """Reversible: the previous status comes back in `undo`."""
        self._require_writable()
        if status not in TICKET_STATUSES:
            raise ValueError(f"status must be one of {', '.join(TICKET_STATUSES)}")

        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT status FROM tickets WHERE tenant_id = ? AND ticket_id = ?",
                (principal.tenant, ticket_id),
            ).fetchone()
            if row is None:
                raise WriteRefused(f"ticket {ticket_id} not found for this tenant")
            previous = row["status"]
            conn.execute(
                "UPDATE tickets SET status = ? WHERE tenant_id = ? AND ticket_id = ?",
                (status, principal.tenant, ticket_id),
            )
            conn.commit()
        finally:
            conn.close()

        return WriteResult(
            changed=previous != status,
            detail={
                "ticket_id": ticket_id,
                "status": status,
                "previous_status": previous,
            },
            undo={
                "tool": "update_ticket_status",
                "arguments": {"ticket_id": ticket_id, "status": previous},
            },
        )

    def refund_invoice(self, invoice_id: str, principal: Principal) -> WriteResult:
        """Irreversible: money left. Nothing here puts it back."""
        self._require_writable()
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT status, amount FROM invoices"
                " WHERE tenant_id = ? AND invoice_id = ?",
                (principal.tenant, invoice_id),
            ).fetchone()
            if row is None:
                raise WriteRefused(f"invoice {invoice_id} not found for this tenant")
            if row["status"] == "refunded":
                return WriteResult(
                    changed=False,
                    detail={
                        "invoice_id": invoice_id,
                        "status": "refunded",
                        "note": "already refunded",
                    },
                    undo=None,
                )
            conn.execute(
                "UPDATE invoices SET status = 'refunded'"
                " WHERE tenant_id = ? AND invoice_id = ?",
                (principal.tenant, invoice_id),
            )
            conn.commit()
            amount = row["amount"]
        finally:
            conn.close()

        return WriteResult(
            changed=True,
            detail={"invoice_id": invoice_id, "status": "refunded", "amount": amount},
            undo=None,
        )

    def grant_access(self, email: str, role: str, principal: Principal) -> WriteResult:
        """Privilege escalation. Revocable, but not by whoever was granted it."""
        self._require_writable()
        if role not in ACCESS_ROLES:
            raise ValueError(f"role must be one of {', '.join(ACCESS_ROLES)}")
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT role FROM agent_access WHERE tenant_id = ? AND email = ?",
                (principal.tenant, email),
            ).fetchone()
            previous = row["role"] if row else None
            conn.execute(
                """
                INSERT INTO agent_access (tenant_id, email, role) VALUES (?, ?, ?)
                ON CONFLICT (tenant_id, email) DO UPDATE SET role = excluded.role
                """,
                (principal.tenant, email, role),
            )
            conn.commit()
        finally:
            conn.close()

        undo: dict[str, Any] | None
        if previous is None:
            undo = {"tool": "revoke_agent_access", "arguments": {"email": email}}
        else:
            undo = {
                "tool": "grant_agent_access",
                "arguments": {"email": email, "role": previous},
            }
        return WriteResult(
            changed=previous != role,
            detail={"email": email, "role": role, "previous_role": previous},
            undo=undo,
        )

    def send_customer_email(
        self, ticket_id: str, body: str, principal: Principal
    ) -> WriteResult:
        """Irreversible and outbound. The two properties that matter, together."""
        self._require_writable()
        conn = self._connect()
        try:
            row = conn.execute(
                """
                SELECT c.email FROM tickets t
                JOIN customers c
                  ON c.tenant_id = t.tenant_id AND c.customer_id = t.customer_id
                WHERE t.tenant_id = ? AND t.ticket_id = ?
                """,
                (principal.tenant, ticket_id),
            ).fetchone()
            if row is None:
                raise WriteRefused(f"ticket {ticket_id} not found for this tenant")
            target = row["email"]
            conn.execute(
                "INSERT INTO outbox (tenant_id, channel, target, body, sent_at)"
                " VALUES (?, 'email', ?, ?, ?)",
                (principal.tenant, target, body, datetime.now(UTC).isoformat()),
            )
            conn.commit()
        finally:
            conn.close()

        return WriteResult(
            changed=True,
            detail={"ticket_id": ticket_id, "recipient": target, "bytes": len(body)},
            undo=None,
        )

    def outbox(self, principal: Principal | None = None) -> list[dict[str, Any]]:
        """What actually left. Read by the security tests, not by any tool."""
        conn = self._connect()
        try:
            if principal is None:
                rows = conn.execute("SELECT * FROM outbox ORDER BY id").fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM outbox WHERE tenant_id = ? ORDER BY id",
                    (principal.tenant,),
                ).fetchall()
        finally:
            conn.close()
        return [dict(r) for r in rows]
