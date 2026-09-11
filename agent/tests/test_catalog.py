"""The declarations every other gate reads."""

from __future__ import annotations

import pytest

from aimai_mcp_agent.catalog import (
    CATALOG,
    ActionClass,
    Capability,
    capabilities_of,
    spec,
)


def test_the_catalog_and_the_pins_describe_the_same_tools():
    import json
    from pathlib import Path

    pins = json.loads(
        (Path(__file__).resolve().parents[1] / "pins.json").read_text(encoding="utf-8")
    )
    assert set(pins["tools"]) == set(CATALOG)


@pytest.mark.parametrize("name", sorted(CATALOG))
def test_every_tool_names_a_server_that_exists(name):
    assert spec(name).server in ("reader", "writer")


def test_only_privilege_escalation_asks_for_a_second_signature():
    for name, tool in CATALOG.items():
        if tool.second_signature:
            assert tool.action is ActionClass.PRIVILEGE_ESCALATION, name


def test_run_query_is_declared_at_its_worst():
    # The static checks run before anyone knows which query a step will ask
    # for, so the declaration has to cover the worst one in the catalogue.
    caps = spec("run_query").capabilities
    assert Capability.SENSITIVE_READ in caps
    assert Capability.UNTRUSTED_INPUT in caps
    assert Capability.EXTERNAL_CHANNEL not in caps


def test_fetch_url_is_both_an_inlet_and_an_outlet():
    caps = spec("fetch_url").capabilities
    assert {Capability.UNTRUSTED_INPUT, Capability.EXTERNAL_CHANNEL} <= caps


def test_refund_is_irreversible_but_not_an_exfiltration_channel():
    # Dangerous on a different axis, and gated by a different control.
    assert spec("refund_invoice").action is ActionClass.IRREVERSIBLE
    assert Capability.EXTERNAL_CHANNEL not in spec("refund_invoice").capabilities


def test_capabilities_of_a_set_is_the_union():
    assert capabilities_of({"list_queries"}) == frozenset()
    assert Capability.EXTERNAL_CHANNEL in capabilities_of({"run_query", "fetch_url"})
