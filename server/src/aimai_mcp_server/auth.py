"""Bearer tokens in, `(tenant, role)` out -- and no third way in.

The whole multi-tenancy guarantee rests on one rule: **no tool takes an
identity argument.** The moment `run_query(tenant="globex", ...)` type-checks,
isolation becomes a matter of the caller's good behaviour, and the caller is a
language model reading text a customer wrote. `tests/test_no_identity_args.py`
fails the build if a tool ever grows such a parameter.

Static tokens are deliberate scope. Minting them properly (OAuth, rotation,
JWKS) is a solved problem with no bearing on what happens after a request is
authenticated, which is what this repo is about. What is *not* skipped is the
refusal path: an unknown or malformed token never reaches a tool.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier

# Ordered from least to most authority; `Principal.at_least` uses the index.
ROLES = ("viewer", "analyst", "admin")

DEFAULT_TOKENS = (
    "tok-acme-viewer:acme:viewer,"
    "tok-acme-analyst:acme:analyst,"
    "tok-acme-admin:acme:admin,"
    "tok-globex-analyst:globex:analyst,"
    "tok-globex-admin:globex:admin"
)


@dataclass(frozen=True)
class Principal:
    tenant: str
    role: str

    def at_least(self, role: str) -> bool:
        return ROLES.index(self.role) >= ROLES.index(role)


def parse_tokens(raw: str) -> dict[str, Principal]:
    """Parse `token:tenant:role,...` into a lookup table.

    Raises on a malformed entry rather than skipping it. A typo in the token
    table that silently drops an entry shows up much later as "the server
    rejects my token", which is the least informative failure available.
    """
    table: dict[str, Principal] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        parts = entry.split(":")
        if len(parts) != 3:
            raise ValueError(f"token entry {entry!r} is not token:tenant:role")
        token, tenant, role = (p.strip() for p in parts)
        if role not in ROLES:
            raise ValueError(f"token entry {entry!r} has unknown role {role!r}")
        if not token or not tenant:
            raise ValueError(f"token entry {entry!r} has an empty token or tenant")
        table[token] = Principal(tenant=tenant, role=role)
    if not table:
        raise ValueError("no tokens configured; set AIMAI_MCP_TOKENS")
    return table


def tokens_from_env() -> dict[str, Principal]:
    return parse_tokens(os.environ.get("AIMAI_MCP_TOKENS", DEFAULT_TOKENS))


class StaticTokenVerifier(TokenVerifier):
    """Looks a bearer token up in a fixed table.

    The tenant and role travel in `claims`, not in `scopes`, because scopes are
    a permission vocabulary and the tenant is not a permission -- conflating
    them is how "scope: tenant:acme" ends up being requestable.
    """

    def __init__(self, table: dict[str, Principal], resource_url: str) -> None:
        self._table = table
        self._resource_url = resource_url

    async def verify_token(self, token: str) -> AccessToken | None:
        principal = self._table.get(token)
        if principal is None:
            return None
        return AccessToken(
            token=token,
            client_id=f"{principal.tenant}:{principal.role}",
            scopes=[f"role:{principal.role}"],
            resource=self._resource_url,
            subject=principal.tenant,
            claims={"tenant": principal.tenant, "role": principal.role},
        )


class Unauthenticated(RuntimeError):
    """Raised when a handler runs without an authenticated principal."""


def current_principal() -> Principal:
    """The principal for the request being handled.

    Reads the access token the transport's auth middleware put in a context
    variable. A handler that reaches this without a token is a configuration
    bug -- the server was started without `auth` -- so it raises rather than
    falling back to a default tenant.
    """
    token = get_access_token()
    if token is None:
        raise Unauthenticated(
            "no authenticated principal; the server must be started with "
            "auth settings and a token verifier"
        )
    claims = token.claims or {}
    tenant, role = claims.get("tenant"), claims.get("role")
    if not tenant or not role:
        raise Unauthenticated("access token carries no tenant/role claims")
    return Principal(tenant=str(tenant), role=str(role))
