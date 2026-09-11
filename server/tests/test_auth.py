"""Tokens in, principals out -- and nothing in between."""

from __future__ import annotations

import pytest

from aimai_mcp_server.auth import (
    Principal,
    StaticTokenVerifier,
    Unauthenticated,
    current_principal,
    parse_tokens,
)


def test_a_token_table_parses():
    table = parse_tokens("a:acme:viewer, b:globex:admin")
    assert table["a"] == Principal("acme", "viewer")
    assert table["b"] == Principal("globex", "admin")


@pytest.mark.parametrize("raw", ["a:acme", "a:acme:wizard", "a::viewer", ""])
def test_a_malformed_table_raises_instead_of_skipping(raw):
    with pytest.raises(ValueError):
        parse_tokens(raw)


def test_roles_are_ordered():
    assert Principal("acme", "admin").at_least("analyst")
    assert not Principal("acme", "viewer").at_least("analyst")


async def test_an_unknown_token_verifies_to_nothing():
    verifier = StaticTokenVerifier(parse_tokens("a:acme:viewer"), "http://x/mcp")
    assert await verifier.verify_token("nope") is None


async def test_the_tenant_travels_in_claims_not_in_scopes():
    # A scope is a permission vocabulary; a tenant is not a permission.
    # Putting it in `scopes` is how "scope: tenant:acme" becomes requestable.
    verifier = StaticTokenVerifier(parse_tokens("a:acme:analyst"), "http://x/mcp")
    token = await verifier.verify_token("a")
    assert token.claims == {"tenant": "acme", "role": "analyst"}
    assert token.scopes == ["role:analyst"]
    assert not any("acme" in s for s in token.scopes)


def test_a_handler_without_a_principal_raises_rather_than_defaulting():
    # The dangerous alternative is a default tenant, which turns a
    # misconfigured server into a silent cross-tenant read.
    with pytest.raises(Unauthenticated):
        current_principal()
