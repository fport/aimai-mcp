"""DNS-rebinding protection: kept on, and configured for where it runs."""

from __future__ import annotations

from aimai_mcp_server.server import transport_security


def test_it_is_on_by_default():
    # Switching it off is the easy fix for the 421 and the wrong one: it is
    # what stops a page in an operator's browser from resolving a name to
    # 127.0.0.1 and driving this server.
    assert transport_security("reader").enable_dns_rebinding_protection is True


def test_localhost_and_the_service_name_are_allowed_out_of_the_box():
    hosts = transport_security("reader").allowed_hosts
    assert "127.0.0.1:*" in hosts
    assert "reader:*" in hosts
    assert "writer:*" not in hosts


def test_the_writer_allows_its_own_name_and_not_the_readers():
    hosts = transport_security("writer").allowed_hosts
    assert "writer:*" in hosts
    assert "reader:*" not in hosts


def test_an_explicit_list_replaces_the_defaults(monkeypatch):
    monkeypatch.setenv("AIMAI_MCP_ALLOWED_HOSTS", "mcp.internal:443, gateway:8811")
    settings = transport_security("reader")
    assert settings.allowed_hosts == ["mcp.internal:443", "gateway:8811"]
    assert "https://mcp.internal:443" in settings.allowed_origins
