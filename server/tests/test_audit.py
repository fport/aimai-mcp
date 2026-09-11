"""The audit log keeps the shape of a call and none of its values."""

from __future__ import annotations

import json
import time

from aimai_mcp_server.audit import (
    AuditLog,
    AuditRecord,
    RawArgumentSink,
    hash_value,
    redact,
)


def test_values_are_replaced_by_digests():
    fields, hashes = redact({"ticket_id": "T-4001", "body": "refund me"}, salt="s")
    assert fields == ["body", "ticket_id"]
    assert set(hashes) == {"body", "ticket_id"}
    blob = json.dumps(hashes)
    assert "T-4001" not in blob and "refund me" not in blob


def test_the_same_value_hashes_the_same_way_within_a_run():
    assert hash_value("T-4001", "s") == hash_value("T-4001", "s")
    assert hash_value("T-4001", "s") != hash_value("T-4002", "s")


def test_the_salt_is_what_makes_a_small_id_space_safe():
    # Without a salt, sha256("T-4001") is a lookup: an attacker with the log
    # enumerates four-digit ticket ids in a second.
    assert hash_value("T-4001", "salt-a") != hash_value("T-4001", "salt-b")


def test_nested_arguments_are_hashed_whole_not_walked():
    # Walking them would put the inner keys in the log, and a key like "ssn"
    # names its contents.
    _, hashes = redact({"filter": {"ssn": "123-45-6789"}}, salt="s")
    assert json.dumps(hashes).count("ssn") == 0


def test_the_log_file_never_contains_an_argument_value(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    fields, hashes = redact({"ticket_id": "T-4001"}, salt="s")
    log.write(
        AuditRecord(
            ts=time.time(),
            method="tools/call",
            tool="run_query",
            tenant="acme",
            role="analyst",
            request_id="1",
            arg_fields=fields,
            arg_hashes=hashes,
            status="ok",
            duration_ms=1.0,
            result_bytes=120,
        )
    )
    text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "T-4001" not in text
    assert "run_query" in text and "acme" in text


def test_the_raw_sink_is_a_separate_file_with_a_retention_window(tmp_path):
    sink = RawArgumentSink(tmp_path / "raw.jsonl", retention_days=1)
    now = time.time()
    sink.write(now - 3 * 86400, "run_query", {"ticket_id": "T-4001"})
    sink.write(now, "run_query", {"ticket_id": "T-4002"})

    assert sink.prune(now) == 1
    kept = (tmp_path / "raw.jsonl").read_text(encoding="utf-8")
    assert "T-4002" in kept and "T-4001" not in kept
