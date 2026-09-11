"""What the servers offer must be what was reviewed.

The committed `agent/pins.json` is a record of a decision: someone read these
descriptions and these schemas and agreed the agent could be shown them. This
suite is the part that notices when the servers stop matching it -- which, for
a server run by someone else, is a supply-chain event and not a deployment
detail.

The poisoned description tested here is corpus record `tool-desc-01`. It is
the one attack in the corpus that never reaches the plan lock, because it
arrives before there is a run: it is what `run_query` *claims to be*.
"""

from __future__ import annotations

import json

import pytest
from conftest import load_corpus

from aimai_mcp_agent.client import PinAlarm, ToolGateway
from aimai_mcp_agent.pinning import ToolDescriptor, check_pins, fingerprint, load_pins

POISON = next(r for r in load_corpus("tool_description"))


async def test_the_live_servers_match_the_committed_pins(servers, pins_path):
    # Strict mode raises on any mismatch, so reaching the assertion is the
    # assertion. The explicit check is there to make the failure readable.
    async with ToolGateway(
        reader_url=servers["reader_url"],
        writer_url=servers["writer_url"],
        token="tok-acme-admin",
        pins_path=pins_path,
    ) as gateway:
        assert gateway.mismatches == []
        assert gateway.visible_names == frozenset(load_pins(pins_path))


async def test_a_poisoned_description_does_not_match_its_pin(servers, pins_path):
    async with ToolGateway(
        reader_url=servers["reader_url"],
        writer_url=servers["writer_url"],
        token="tok-acme-admin",
        pins_path=pins_path,
    ) as gateway:
        live = next(t for t in gateway.visible_tools if t.name == "run_query")

    poisoned = ToolDescriptor(live.name, POISON["text"], live.schema)
    result = check_pins([poisoned], load_pins(pins_path))
    assert not result.ok
    assert result.approved == []
    assert result.mismatches[0].kind == "changed"


async def test_a_tampered_pin_file_stops_the_session(servers, pins_path, tmp_path):
    tampered = tmp_path / "pins.json"
    data = json.loads(pins_path.read_text(encoding="utf-8"))
    data["tools"]["run_query"] = "sha256:" + "0" * 64
    tampered.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(PinAlarm, match="run_query"):
        async with ToolGateway(
            reader_url=servers["reader_url"],
            writer_url=servers["writer_url"],
            token="tok-acme-admin",
            pins_path=tampered,
        ):
            pass


async def test_a_mismatched_tool_is_hidden_and_uncallable(servers, pins_path, tmp_path):
    # Non-strict mode is what a monitoring run would use: keep going, but the
    # tool is gone. "Hidden" has to mean uncallable too, or it is decoration.
    tampered = tmp_path / "pins.json"
    data = json.loads(pins_path.read_text(encoding="utf-8"))
    data["tools"]["run_query"] = "sha256:" + "0" * 64
    tampered.write_text(json.dumps(data), encoding="utf-8")

    async with ToolGateway(
        reader_url=servers["reader_url"],
        writer_url=servers["writer_url"],
        token="tok-acme-admin",
        pins_path=tampered,
        strict_pins=False,
    ) as gateway:
        assert "run_query" not in gateway.visible_names
        outcome = await gateway.call("run_query", {"query": "open_tickets"})

    assert not outcome.ok
    assert "not available" in outcome.error


async def test_a_tool_that_appeared_since_the_last_review_is_a_mismatch(
    servers, pins_path, tmp_path
):
    thinned = tmp_path / "pins.json"
    data = json.loads(pins_path.read_text(encoding="utf-8"))
    removed = data["tools"].pop("fetch_url")
    thinned.write_text(json.dumps(data), encoding="utf-8")
    assert removed

    async with ToolGateway(
        reader_url=servers["reader_url"],
        writer_url=servers["writer_url"],
        token="tok-acme-admin",
        pins_path=thinned,
        strict_pins=False,
    ) as gateway:
        kinds = {m.tool: m.kind for m in gateway.mismatches}

    assert kinds == {"fetch_url": "unpinned"}


def test_the_fingerprint_covers_the_description_not_just_the_name():
    # Stated as its own test because it is the assumption everything above
    # rests on: a poisoned tool keeps its name and its schema.
    base = ToolDescriptor("run_query", "Run one named query.", {"type": "object"})
    poisoned = ToolDescriptor("run_query", POISON["text"], {"type": "object"})
    assert base.name == poisoned.name
    assert base.schema == poisoned.schema
    assert fingerprint(base) != fingerprint(poisoned)
