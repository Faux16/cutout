"""Live auth-conformance probe for an authorized, running MCP server.

The offline corpus classifies servers from source; this probes a *running* server for the
observable half of MCP 2026-07-28 auth conformance — benignly, and by default without any
credentials:

* **RFC 9728 discovery** — does it serve ``/.well-known/oauth-protected-resource`` naming its
  authorization server(s) and canonical resource?
* **RFC 6750 / MCP challenge** — does an unauthenticated request get a ``401`` carrying a
  ``WWW-Authenticate: Bearer resource_metadata=…`` challenge (vs being open, or a bare 401)?

The audience/issuer *binding* itself cannot be tested without a validly-signed token the
server's IdP would accept — rejecting a bad-signature token proves nothing. That needs the
operator's own credentials. When the operator supplies ``foreign_token`` (a token they are
authorized to use that was issued for ANOTHER audience/issuer), the probe presents it:
acceptance is a live confused-deputy finding (``standin`` / ``shellgame``). ``valid_token`` is
the control — the legitimate path still works.

Authorized use only: your own server and your own tokens. We never mint, phish, or guess a
token. See ETHICS.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

_WELL_KNOWN = "/.well-known/oauth-protected-resource"

#: A minimal, side-effect-free MCP request used to elicit the auth decision.
_INIT_BODY: dict[str, Any] = {
    "jsonrpc": "2.0",
    "id": "cutout-authconf-probe",
    "method": "initialize",
    "params": {
        "protocolVersion": "2026-07-28",
        "capabilities": {},
        "clientInfo": {"name": "cutout-authconf", "version": "0"},
    },
}
_MCP_HEADERS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}


def normalize_target(url: str) -> str:
    """Normalize an ``mcp://`` / ``mcp+http(s)://`` / ``http(s)://`` target to an HTTP URL."""
    u = url.strip()
    if u.startswith("mcp+http://") or u.startswith("mcp+https://"):
        return u[len("mcp+") :]
    if u.startswith("mcp://"):
        return "http://" + u[len("mcp://") :]
    if u.startswith(("http://", "https://")):
        return u
    return "https://" + u  # bare host:port/path -> assume https


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


@dataclass(slots=True)
class TargetProbe:
    """What a live probe could observe about one server's auth-conformance posture."""

    url: str
    discovery_ok: bool | None = None  # RFC 9728 metadata present + names an authorization server
    discovery_detail: str = ""
    challenge_ok: bool | None = None  # 401 + WWW-Authenticate: Bearer resource_metadata=…
    challenge_detail: str = ""
    auth_required: bool | None = None  # an unauthenticated request is NOT served
    foreign_rejected: bool | None = None  # a supplied foreign-audience/issuer token is rejected
    foreign_detail: str = ""
    valid_accepted: bool | None = None  # control: a supplied valid token is accepted
    valid_detail: str = ""
    notes: list[str] = field(default_factory=list)

    @property
    def binding_tested(self) -> bool:
        """Whether the audience/issuer *binding* was actually exercised (needs a foreign token)."""
        return self.foreign_rejected is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "discovery_ok": self.discovery_ok,
            "discovery_detail": self.discovery_detail,
            "challenge_ok": self.challenge_ok,
            "challenge_detail": self.challenge_detail,
            "auth_required": self.auth_required,
            "foreign_rejected": self.foreign_rejected,
            "foreign_detail": self.foreign_detail,
            "valid_accepted": self.valid_accepted,
            "valid_detail": self.valid_detail,
            "binding_tested": self.binding_tested,
            "notes": list(self.notes),
        }


async def _discovery(client: httpx.AsyncClient, origin: str) -> tuple[bool | None, str]:
    try:
        resp = await client.get(origin + _WELL_KNOWN, headers={"Accept": "application/json"})
    except httpx.HTTPError as exc:
        return None, f"request failed: {type(exc).__name__}"
    if resp.status_code != 200:
        return False, f"no RFC 9728 metadata (HTTP {resp.status_code})"
    try:
        data = resp.json()
    except ValueError:
        return False, "metadata endpoint did not return JSON"
    servers = data.get("authorization_servers")
    resource = data.get("resource")
    if servers:
        return True, f"resource={resource!r}, authorization_servers={servers}"
    return False, "metadata present but names no authorization_servers"


async def _challenge(client: httpx.AsyncClient, url: str) -> tuple[bool | None, str, bool | None]:
    try:
        resp = await client.post(url, json=_INIT_BODY, headers=_MCP_HEADERS)
    except httpx.HTTPError as exc:
        return None, f"request failed: {type(exc).__name__}", None
    status = resp.status_code
    if status in (401, 403):
        www = resp.headers.get("www-authenticate", "")
        if "resource_metadata" in www.lower():
            return True, f"HTTP {status} + WWW-Authenticate resource_metadata", True
        return False, f"HTTP {status} but WWW-Authenticate lacks resource_metadata", True
    if status < 400:
        return False, f"unauthenticated request was served (HTTP {status})", False
    return None, f"inconclusive (HTTP {status})", None


async def _token_outcome(
    client: httpx.AsyncClient, url: str, token: str
) -> tuple[bool | None, str]:
    """Return (rejected, detail): True if 401/403, False if 2xx, None if inconclusive."""
    headers = {**_MCP_HEADERS, "Authorization": f"Bearer {token}"}
    try:
        resp = await client.post(url, json=_INIT_BODY, headers=headers)
    except httpx.HTTPError as exc:
        return None, f"request failed: {type(exc).__name__}"
    status = resp.status_code
    if status in (401, 403):
        return True, f"rejected (HTTP {status})"
    if status < 400:
        return False, f"accepted (HTTP {status})"
    return None, f"inconclusive (HTTP {status})"


async def probe_target(
    url: str,
    *,
    valid_token: str | None = None,
    foreign_token: str | None = None,
    client: httpx.AsyncClient | None = None,
    timeout: float = 15.0,
) -> TargetProbe:
    """Probe an authorized MCP server for observable auth-conformance (see module docstring)."""
    target = normalize_target(url)
    probe = TargetProbe(url=target)
    own = client is None
    http = client or httpx.AsyncClient(timeout=timeout, follow_redirects=True)
    try:
        probe.discovery_ok, probe.discovery_detail = await _discovery(http, _origin(target))
        probe.challenge_ok, probe.challenge_detail, probe.auth_required = await _challenge(
            http, target
        )
        if foreign_token:
            probe.foreign_rejected, probe.foreign_detail = await _token_outcome(
                http, target, foreign_token
            )
        if valid_token:
            accepted, detail = await _token_outcome(http, target, valid_token)
            probe.valid_accepted = None if accepted is None else (not accepted)
            probe.valid_detail = detail
    finally:
        if own:
            await http.aclose()

    if probe.auth_required is False:
        probe.notes.append("server served an unauthenticated request — no OAuth enforcement")
    if not probe.binding_tested:
        probe.notes.append(
            "audience/issuer binding NOT directly tested — supply a foreign token "
            "(authorized) to exercise it; discovery/challenge posture only"
        )
    elif probe.foreign_rejected is False:
        probe.notes.append(
            "EXPOSED: accepted a token issued for another audience/issuer — live "
            "confused-deputy (standin/shellgame). Confirm the token's aud/iss and disclose."
        )
    if probe.valid_accepted is False:
        probe.notes.append("control: the supplied valid token was NOT accepted — check inputs")
    return probe
