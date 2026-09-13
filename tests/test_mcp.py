"""The range's tool servers speak real MCP (official SDK) with transport (bearer) auth.

Enumeration and the deny-without-auth path are checked in-memory (fast, hermetic). The
allowed path needs a real connection carrying an Authorization header, so one test runs a
throwaway uvicorn server on a loopback port and drives it with the same MCP client the
orchestrator uses.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import Iterator

import pytest

pytest.importorskip("mcp")
pytest.importorskip("uvicorn")

from cutout_range.range import BILLING_TOKEN, DELEGATED_TOKEN
from cutout_range.service import mcp_client
from cutout_range.service.mcp_servers import (
    customer_data_server,
    http_app,
    payments_server,
)
from mcp.client import Client


def _parse(result: object) -> dict:
    return json.loads(result.content[0].text)  # type: ignore[attr-defined]


# ---- in-memory (no transport) -------------------------------------------------
async def test_enumeration_flags_sensitive_via_meta() -> None:
    async with Client(customer_data_server(DELEGATED_TOKEN)) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
    # Sensitivity is advertised via meta, and the credential is NOT a tool argument.
    assert tools["get_customer_secret"].meta == {"sensitive": True}
    assert "authorization" not in tools["get_customer_secret"].input_schema["properties"]
    assert list(tools["get_customer_secret"].input_schema["properties"]) == ["id"]
    assert not (tools["search_customers"].meta or {}).get("sensitive")


async def test_sensitive_denied_without_transport_auth() -> None:
    # In-memory there is no Authorization header, so the sensitive tool refuses.
    async with Client(customer_data_server(DELEGATED_TOKEN)) as c:
        denied = _parse(await c.call_tool("get_customer_secret", {"id": "VIP-001"}))
        benign = _parse(await c.call_tool("search_customers", {"query": "acme"}))
    assert denied["ok"] is False
    assert benign["ok"] is True


# ---- real transport (bearer header over HTTP) ---------------------------------
@pytest.fixture
def live_customer_data() -> Iterator[str]:
    import uvicorn

    app = http_app(customer_data_server(DELEGATED_TOKEN))
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started, "uvicorn did not start"
    try:
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        server.should_exit = True
        thread.join(timeout=5)


async def test_transport_auth_gates_sensitive_tool(live_customer_data: str) -> None:
    url = live_customer_data
    # Enumeration is unauthenticated; the sensitive tool is flagged via meta.
    tools = {t["name"]: t for t in await mcp_client.list_tools(url)}
    assert tools["get_customer_secret"]["sensitive"] is True

    # No bearer -> denied; correct bearer -> the secret comes back.
    denied = await mcp_client.call_tool(url, "get_customer_secret", {"id": "VIP-001"})
    assert denied["ok"] is False
    allowed = await mcp_client.call_tool(
        url, "get_customer_secret", {"id": "VIP-001"}, token=DELEGATED_TOKEN
    )
    assert allowed["ok"] is True
    assert "cutrange_FAKE_secret_VIP001" in allowed["data"]["api_secret"]

    # A wrong token is rejected too.
    wrong = await mcp_client.call_tool(
        url, "get_customer_secret", {"id": "VIP-001"}, token=BILLING_TOKEN
    )
    assert wrong["ok"] is False


async def test_payments_server_builds() -> None:
    async with Client(payments_server(BILLING_TOKEN)) as c:
        names = {t.name for t in (await c.list_tools()).tools}
    assert {"issue_refund", "list_refunds"} <= names
