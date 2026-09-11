"""Caps are applied where the rows are, not where they land."""

from __future__ import annotations

import pytest

from aimai_mcp_server.limits import ELLIPSIS, Limits, clamp_page, shape_result


def test_a_huge_limit_is_clamped_not_refused():
    assert clamp_page(5000, 0) == (200, 0)


def test_defaults_apply_when_nothing_is_asked_for():
    assert clamp_page(None, None) == (20, 0)


@pytest.mark.parametrize("limit,offset", [(0, 0), (-1, 0), (10, -5)])
def test_nonsense_pages_raise(limit, offset):
    with pytest.raises(ValueError):
        clamp_page(limit, offset)


def test_booleans_are_not_integers_here():
    # `True` is an int in Python and would silently become limit=1.
    with pytest.raises(ValueError):
        clamp_page(True, 0)


def test_a_long_cell_is_cut_and_flagged():
    limits = Limits(max_cell_chars=10)
    out = shape_result(
        [{"body": "x" * 50}], limit=20, offset=0, had_more=False, limits=limits
    )
    assert out["rows"][0]["body"] == "x" * 10 + ELLIPSIS
    assert out["truncated"] is True
    assert out["truncated_by"] == ["cell"]


def test_more_rows_available_sets_next_offset():
    out = shape_result([{"a": 1}], limit=1, offset=4, had_more=True)
    assert out["truncated"] is True
    assert out["truncated_by"] == ["rows"]
    assert out["next_offset"] == 5


def test_the_total_budget_stops_a_wide_page():
    limits = Limits(max_total_chars=30)
    rows = [{"body": "y" * 20} for _ in range(5)]
    out = shape_result(rows, limit=5, offset=0, had_more=False, limits=limits)
    assert out["row_count"] == 1
    assert "total_chars" in out["truncated_by"]


def test_an_untruncated_page_says_so():
    out = shape_result([{"a": 1}], limit=20, offset=0, had_more=False)
    assert out["truncated"] is False
    assert out["next_offset"] is None
