"""Audit middleware: every call recorded, no argument value recorded.

An audit log that stores raw arguments is a second copy of the data the access
controls exist to protect, usually with weaker controls and longer retention
than the database. So this one keeps the *shape* of every call -- which tool,
which tenant, which role, which argument names, how big the result, how long
it took, what happened -- and replaces each value with a salted digest.

The digest is still useful: two calls with the same ticket id share a hash, so
"the same record was read 40 times in a minute" is answerable without the log
knowing which record. Salted, because ticket ids come from a space small
enough to enumerate -- an unsalted SHA-256 of `T-4001` is a lookup, not a
redaction.

Raw values, when an investigation genuinely needs them, go to a separate sink
that is off by default, written to a different file, and documented with a
retention window. That is a deliberate second decision someone has to make,
not a flag that quietly widens what the normal log holds.

This is not bookkeeping. Every number in the README's measurement table is a
query over these records; without the middleware there is nothing to measure.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mcp.server.auth.middleware.auth_context import get_access_token

HASH_PREFIX_LEN = 12


@dataclass
class AuditRecord:
    ts: float
    method: str
    tool: str | None
    tenant: str | None
    role: str | None
    request_id: str | None
    arg_fields: list[str]
    arg_hashes: dict[str, str]
    status: str
    duration_ms: float
    result_bytes: int = 0
    truncated: bool = False
    error: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class AuditLog:
    """Append-only JSONL sink plus an in-memory tail for tests and scripts."""

    def __init__(self, path: str | Path | None = None, *, keep: int = 2000) -> None:
        self.path = Path(path) if path else None
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._keep = keep
        self.records: list[AuditRecord] = []

    def write(self, record: AuditRecord) -> None:
        self.records.append(record)
        if len(self.records) > self._keep:
            del self.records[: len(self.records) - self._keep]
        if self.path is not None:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(asdict(record), ensure_ascii=False) + "\n")


class RawArgumentSink:
    """The separate, restricted, time-boxed record of raw arguments.

    Off unless `AIMAI_MCP_RAW_AUDIT` names a file. Kept apart from `AuditLog`
    so that "who can read the audit log" and "who can read the arguments" stay
    two different answers.
    """

    def __init__(self, path: str | Path, *, retention_days: int = 7) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.retention_days = retention_days

    def write(self, ts: float, tool: str | None, arguments: Mapping[str, Any]) -> None:
        entry = {
            "ts": ts,
            "tool": tool,
            "arguments": dict(arguments),
            "expires_at": ts + self.retention_days * 86400,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def prune(self, now: float | None = None) -> int:
        """Drop expired lines. Retention nobody enforces is not retention."""
        if not self.path.exists():
            return 0
        now = time.time() if now is None else now
        kept, dropped = [], 0
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("expires_at", 0) > now:
                kept.append(line)
            else:
                dropped += 1
        self.path.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
        return dropped


def hash_value(value: Any, salt: str) -> str:
    """Salted, truncated digest of one argument value.

    Containers are hashed through their canonical JSON so that `{"a": 1}` and
    `{"a": 1}` agree while `[1, 2]` and `[2, 1]` do not.
    """
    if isinstance(value, str):
        payload = value
    else:
        payload = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    digest = hashlib.sha256((salt + "\x00" + payload).encode("utf-8")).hexdigest()
    return f"sha256:{digest[:HASH_PREFIX_LEN]}"


def redact(arguments: Mapping[str, Any], salt: str) -> tuple[list[str], dict[str, str]]:
    """Field names kept, values replaced by digests -- one level deep only.

    Nested structures are hashed whole rather than walked. Walking them would
    put nested *keys* in the log, and keys are data too: `{"ssn": ...}` names
    the thing it holds.
    """
    fields = sorted(arguments)
    return fields, {name: hash_value(arguments[name], salt) for name in fields}


class AuditMiddleware:
    """`ServerMiddleware`: wraps every inbound request and notification.

    Sits at the context tier, which means it sees the method and the raw params
    before validation and still observes a handler that raised. Both matter: a
    call rejected for a malformed argument is exactly the call an audit trail
    should contain.
    """

    def __init__(
        self,
        log: AuditLog,
        *,
        salt: str | None = None,
        raw_sink: RawArgumentSink | None = None,
    ) -> None:
        self.log = log
        # A per-process salt means digests are comparable within a run and not
        # across runs. Set AIMAI_MCP_AUDIT_SALT to compare across restarts.
        self.salt = (
            salt or os.environ.get("AIMAI_MCP_AUDIT_SALT") or secrets.token_hex(16)
        )
        self.raw_sink = raw_sink

    async def __call__(self, ctx: Any, call_next: Any) -> Any:
        started = time.perf_counter()
        params = ctx.params or {}
        tool = params.get("name") if ctx.method == "tools/call" else None
        arguments = params.get("arguments") or {} if ctx.method == "tools/call" else {}
        if not isinstance(arguments, Mapping):
            arguments = {"_malformed": str(type(arguments).__name__)}

        tenant = role = None
        token = get_access_token()
        if token is not None:
            claims = token.claims or {}
            tenant, role = claims.get("tenant"), claims.get("role")

        fields, hashes = redact(arguments, self.salt)
        status, error, result_bytes, truncated = "ok", None, 0, False

        try:
            result = await call_next(ctx)
        except Exception as exc:
            status, error = "error", type(exc).__name__
            self._record(
                ctx,
                tool,
                tenant,
                role,
                fields,
                hashes,
                status,
                started,
                result_bytes,
                truncated,
                error,
                arguments,
            )
            raise

        result_bytes, truncated, status = self._inspect(result, status)
        self._record(
            ctx,
            tool,
            tenant,
            role,
            fields,
            hashes,
            status,
            started,
            result_bytes,
            truncated,
            error,
            arguments,
        )
        return result

    @staticmethod
    def _inspect(result: Any, status: str) -> tuple[int, bool, str]:
        """Size, truncation and tool-level failure, read off the result.

        A tool that raises comes back as a *successful* `tools/call` carrying
        `isError`, so a middleware that only watches for exceptions records a
        failed call as a clean one.
        """
        payload = result
        if hasattr(result, "model_dump"):
            try:
                payload = result.model_dump(mode="json")
            except Exception:  # pragma: no cover - defensive
                payload = None
        if payload is None:
            return 0, False, status

        try:
            encoded = json.dumps(payload, ensure_ascii=False, default=str)
        except (TypeError, ValueError):  # pragma: no cover - defensive
            return 0, False, status

        size = len(encoded)
        truncated = '"truncated": true' in encoded or '"truncated":true' in encoded
        if isinstance(payload, dict) and payload.get("isError"):
            status = "tool_error"
        return size, truncated, status

    def _record(
        self,
        ctx: Any,
        tool: str | None,
        tenant: str | None,
        role: str | None,
        fields: list[str],
        hashes: dict[str, str],
        status: str,
        started: float,
        result_bytes: int,
        truncated: bool,
        error: str | None,
        arguments: Mapping[str, Any],
    ) -> None:
        now = time.time()
        self.log.write(
            AuditRecord(
                ts=now,
                method=ctx.method,
                tool=tool,
                tenant=str(tenant) if tenant else None,
                role=str(role) if role else None,
                request_id=str(ctx.request_id) if ctx.request_id is not None else None,
                arg_fields=fields,
                arg_hashes=hashes,
                status=status,
                duration_ms=round((time.perf_counter() - started) * 1000, 3),
                result_bytes=result_bytes,
                truncated=truncated,
                error=error,
            )
        )
        if self.raw_sink is not None and arguments:
            self.raw_sink.write(now, tool, arguments)
