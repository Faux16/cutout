"""A minimal OAuth-style token model for the MCP 2026-07-28 authorization surface.

The 2026-07-28 MCP spec is emphatic: an MCP server **MUST only accept tokens specifically
intended for itself** (RFC 8707 audience binding) and **token passthrough is explicitly
forbidden**. A server that accepts a token minted for a *different* audience — or forwards a
client's token upstream — becomes a confused deputy, acting on credentials that were never
meant for it. That is the class behind much of the 2026 MCP CVE wave.

This models it offline: an :class:`AuthServer` mints :class:`Token`\\ s bound to an ``audience``
(the resource they were issued for) and an ``issuer`` (the AS that minted them); a
:class:`ResourceServer` either validates those (hardened, per RFC 8707 / RFC 9207) or accepts any
token the AS issued (vulnerable — the non-compliant norm). Exploited by CUT-EXEC-005 (``standin``).
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any

DEFAULT_ISSUER = "https://auth.cutout-range.local"


@dataclass(frozen=True, slots=True)
class Token:
    """An access token bound to the resource it was issued for and the AS that minted it."""

    value: str
    audience: str  # the resource the token is intended for (RFC 8707 resource indicator)
    issuer: str  # the authorization server that minted it (RFC 9207)


@dataclass(frozen=True, slots=True)
class AuthCode:
    """An OAuth authorization code — exchangeable for a token at the AS that issued it."""

    value: str
    audience: str
    issuer: str


@dataclass(frozen=True, slots=True)
class AuthResponse:
    """An authorization response delivered to a client, carrying the code and the ``iss`` of the
    authorization server that (claims to have) issued it — the field RFC 9207 makes clients
    validate to detect a mix-up."""

    code: AuthCode
    iss: str


class AuthServer:
    """A stand-in OAuth 2.1 authorization server: it mints audience-bound tokens and codes, and
    (when attacker-controlled) captures codes a confused client hands it."""

    def __init__(self, issuer: str = DEFAULT_ISSUER) -> None:
        self.issuer = issuer
        self.captured: list[AuthCode] = []  # codes delivered to this AS (an attacker's loot)

    def mint(self, audience: str) -> Token:
        return Token(value="at_" + secrets.token_hex(8), audience=audience, issuer=self.issuer)

    def authorize(self, audience: str) -> AuthCode:
        return AuthCode(value="ac_" + secrets.token_hex(8), audience=audience, issuer=self.issuer)

    def redeem(self, code: AuthCode) -> Token | None:
        """Exchange a code for a token — but only a code THIS server actually issued."""
        if code.issuer != self.issuer:
            return None
        return self.mint(code.audience)

    def receive_code(self, code: AuthCode) -> None:
        """A client delivered a code here; an attacker-controlled AS records it as loot."""
        self.captured.append(code)


@dataclass(slots=True)
class Client:
    """An MCP OAuth client completing an authorization flow it started with ``expected_issuer``.

    ``validate_iss`` (RFC 9207) is the mix-up mitigation: a compliant client rejects an
    authorization response whose ``iss`` does not match the AS it started the flow with. Without
    it, an attacker-controlled AS can make the client deliver a code issued by the honest AS to
    the attacker (an authorization-server mix-up)."""

    expected_issuer: str
    validate_iss: bool = False

    def complete(self, response: AuthResponse, servers: dict[str, AuthServer]) -> dict[str, Any]:
        if self.validate_iss and response.iss != self.expected_issuer:
            return {
                "ok": False,
                "rejected": True,
                "leaked": False,
                "error": (
                    f"authorization response issuer '{response.iss}' does not match the "
                    f"server the flow started with ('{self.expected_issuer}') — mix-up rejected"
                ),
            }
        target = servers.get(response.iss)
        if target is None:
            return {"ok": False, "rejected": False, "leaked": False, "error": "unknown issuer"}
        target.receive_code(response.code)  # send the code where the response says it came from
        return {
            "ok": True,
            "rejected": False,
            "delivered_to": response.iss,
            "leaked": response.iss != self.expected_issuer,
        }


@dataclass(slots=True)
class ResourceServer:
    """An MCP resource server holding protected data behind a bearer token.

    ``validate_audience`` (RFC 8707) and ``trusted_issuer`` (RFC 9207) are the 2026-07-28
    mitigations. With both off — the vulnerable default modeling a non-compliant server — it
    accepts *any* token the AS issued, so a token minted for another audience is honored: the
    confused-deputy / token-passthrough flaw.
    """

    id: str
    audience: str
    data: dict[str, Any] = field(default_factory=dict)
    validate_audience: bool = False
    trusted_issuer: str | None = None

    def access(self, token: Token | None) -> dict[str, Any]:
        if token is None:
            return {"ok": False, "error": "no token presented"}
        if self.trusted_issuer is not None and token.issuer != self.trusted_issuer:
            return {"ok": False, "error": f"untrusted issuer '{token.issuer}'"}
        if self.validate_audience and token.audience != self.audience:
            return {
                "ok": False,
                "error": (
                    f"token audience '{token.audience}' was not issued for this server "
                    f"(expected '{self.audience}')"
                ),
            }
        return {"ok": True, "data": dict(self.data)}
