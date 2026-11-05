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


class AuthServer:
    """Mints audience-bound access tokens (a stand-in for an OAuth 2.1 authorization server)."""

    def __init__(self, issuer: str = DEFAULT_ISSUER) -> None:
        self.issuer = issuer

    def mint(self, audience: str) -> Token:
        return Token(value="at_" + secrets.token_hex(8), audience=audience, issuer=self.issuer)


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
