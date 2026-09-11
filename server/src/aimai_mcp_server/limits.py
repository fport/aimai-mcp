"""Result caps and pagination, applied on the server.

Truncating on the client is not truncating. The rows have already crossed the
network, already been logged by whatever sits in between, and already left the
process that was allowed to read them. The only cut that limits exposure is
the one made before the result is serialized, so every cap here runs inside
the tool handler.

Three caps, because they fail differently: a row cap bounds how much of a
table one call can pull, a cell cap bounds a single pathological value (a
10 MB note body), and a total-character cap bounds the combination -- 50 rows
of 500 characters is still 25 000 characters of context.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

ELLIPSIS = "...[truncated]"


@dataclass(frozen=True)
class Limits:
    default_rows: int = 20
    max_rows: int = 200
    max_cell_chars: int = 500
    max_total_chars: int = 20_000


LIMITS = Limits()


def clamp_page(
    limit: int | None, offset: int | None, limits: Limits = LIMITS
) -> tuple[int, int]:
    """Normalise `limit`/`offset` into a page the server is willing to serve.

    A caller asking for 10 000 rows gets `max_rows`, not an error: the request
    is answerable, just not at that size, and the `truncated` flag in the
    result says so. A negative offset is a bug, not a request, so it raises.
    """
    if limit is None:
        limit = limits.default_rows
    if offset is None:
        offset = 0
    if not isinstance(limit, int) or isinstance(limit, bool):
        raise ValueError("limit must be an integer")
    if not isinstance(offset, int) or isinstance(offset, bool):
        raise ValueError("offset must be an integer")
    if limit < 1:
        raise ValueError("limit must be at least 1")
    if offset < 0:
        raise ValueError("offset must not be negative")
    return min(limit, limits.max_rows), offset


def clip_cell(value: Any, limits: Limits = LIMITS) -> tuple[Any, bool]:
    """Shorten one cell, reporting whether it was cut."""
    if not isinstance(value, str) or len(value) <= limits.max_cell_chars:
        return value, False
    return value[: limits.max_cell_chars] + ELLIPSIS, True


def shape_result(
    rows: list[dict[str, Any]],
    *,
    limit: int,
    offset: int,
    had_more: bool,
    limits: Limits = LIMITS,
) -> dict[str, Any]:
    """Apply the cell and total caps and describe what was cut.

    `truncated` is one flag for three different cuts on purpose: the caller's
    next move is the same in all three cases -- ask for the next page, or ask
    a narrower question. `truncated_by` is there for the audit log and for a
    human reading a transcript.
    """
    reasons: list[str] = []
    if had_more:
        reasons.append("rows")

    clipped: list[dict[str, Any]] = []
    total = 0
    for row in rows:
        out: dict[str, Any] = {}
        for key, value in row.items():
            value, was_clipped = clip_cell(value, limits)
            if was_clipped and "cell" not in reasons:
                reasons.append("cell")
            out[key] = value
        row_chars = sum(len(str(v)) for v in out.values())
        if total + row_chars > limits.max_total_chars:
            if "total_chars" not in reasons:
                reasons.append("total_chars")
            break
        total += row_chars
        clipped.append(out)

    return {
        "rows": clipped,
        "row_count": len(clipped),
        "offset": offset,
        "limit": limit,
        "truncated": bool(reasons),
        "truncated_by": reasons,
        "next_offset": offset + len(clipped) if reasons else None,
    }
