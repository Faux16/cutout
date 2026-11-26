"""Live auth-conformance probe — driven against in-process ASGI servers (no network)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest
from cutout.auth_target import normalize_target, probe_target

_WK = "/.well-known/oauth-protected-resource"


def _make_app(*, conformant: bool) -> Callable[..., Any]:
    async def app(scope: dict, receive: Callable, send: Callable) -> None:
        assert scope["type"] == "http"
        path, method = scope["path"], scope["method"]
        headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
        while True:  # drain the request body
            msg = await receive()
            if not msg.get("more_body"):
                break

        async def respond(status: int, body: bytes, extra: dict[str, str] | None = None) -> None:
            hdrs = [(b"content-type", b"application/json")]
            for k, v in (extra or {}).items():
                hdrs.append((k.encode(), v.encode()))
            await send({"type": "http.response.start", "status": status, "headers": hdrs})
            await send({"type": "http.response.body", "body": body})

        if path == _WK and method == "GET":
            if conformant:
                await respond(
                    200,
                    b'{"resource":"https://ts/mcp","authorization_servers":["https://as.example"]}',
                )
            else:
                await respond(404, b'{"error":"not found"}')
            return
        if path == "/mcp" and method == "POST":
            if not conformant:  # open server: serves anything, with or without a token
                await respond(200, b'{"jsonrpc":"2.0","id":"x","result":{}}')
                return
            auth = headers.get("authorization", "")
            if not auth:
                await respond(
                    401,
                    b'{"error":"unauthorized"}',
                    {"WWW-Authenticate": 'Bearer resource_metadata="https://ts' + _WK + '"'},
                )
            elif auth == "Bearer valid-xyz":
                await respond(200, b'{"jsonrpc":"2.0","id":"x","result":{}}')
            else:  # a token not issued for this server
                await respond(401, b'{"error":"invalid_token"}')
            return
        await respond(404, b"{}")

    return app


def _client(app: Callable[..., Any]) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://ts")


def test_normalize_target() -> None:
    assert normalize_target("mcp://h/mcp") == "http://h/mcp"
    assert normalize_target("mcp+https://h/mcp") == "https://h/mcp"
    assert normalize_target("https://h/mcp") == "https://h/mcp"
    assert normalize_target("h:8080/mcp") == "https://h:8080/mcp"


async def test_conformant_server_passes_discovery_and_challenge() -> None:
    async with _client(_make_app(conformant=True)) as c:
        probe = await probe_target("http://ts/mcp", client=c)
    assert probe.discovery_ok is True
    assert probe.challenge_ok is True
    assert probe.auth_required is True
    assert probe.binding_tested is False  # no foreign token supplied
    assert any("NOT directly tested" in n for n in probe.notes)


async def test_conformant_server_rejects_foreign_token_accepts_valid() -> None:
    async with _client(_make_app(conformant=True)) as c:
        probe = await probe_target(
            "http://ts/mcp", client=c, valid_token="valid-xyz", foreign_token="foreign-abc"
        )
    assert probe.foreign_rejected is True  # a token not for this server is rejected
    assert probe.valid_accepted is True  # the control path works
    assert probe.binding_tested is True
    assert not any("EXPOSED" in n for n in probe.notes)


async def test_open_server_is_flagged_and_exposed() -> None:
    async with _client(_make_app(conformant=False)) as c:
        probe = await probe_target("http://ts/mcp", client=c, foreign_token="foreign-abc")
    assert probe.discovery_ok is False
    assert probe.auth_required is False
    assert probe.foreign_rejected is False  # accepted a token issued for another audience/issuer
    assert any("no OAuth enforcement" in n for n in probe.notes)
    assert any("EXPOSED" in n for n in probe.notes)


async def test_unreachable_target_is_inconclusive_not_crash() -> None:
    # A real connection failure (closed port) yields inconclusive checks, never an exception.
    async with httpx.AsyncClient(timeout=0.3) as c:
        probe = await probe_target("http://127.0.0.1:0/mcp", client=c)
    assert probe.discovery_ok is None and probe.challenge_ok is None


def test_probe_result_serializes() -> None:
    from cutout.auth_target import TargetProbe

    d = TargetProbe(url="http://ts/mcp").to_dict()
    assert d["url"] == "http://ts/mcp" and "binding_tested" in d and "notes" in d


@pytest.mark.parametrize("conformant", [True, False])
async def test_probe_target_owns_client_when_not_injected(conformant: bool) -> None:
    # Smoke: with no injected client it builds and closes its own; a bad host is inconclusive.
    probe = await probe_target("http://127.0.0.1:0/mcp", timeout=0.2)
    assert probe.discovery_ok in (None, False)
