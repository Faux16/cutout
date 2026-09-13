"""The range's tool servers speak real MCP (official SDK), with auth-gated tools.

Driven in-memory via the high-level Client over the MCPServer objects — no HTTP, no
network — so this stays fast and hermetic in CI.
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("mcp")

from cutout_range.range import BILLING_TOKEN, DELEGATED_TOKEN
from cutout_range.service.mcp_servers import (
    customer_data_server,
    payments_server,
)
from mcp.client import Client


def _parse(result: object) -> dict:
    return json.loads(result.content[0].text)  # type: ignore[attr-defined]


async def test_mcp_lists_tools_with_schemas() -> None:
    async with Client(customer_data_server(DELEGATED_TOKEN)) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
    assert {"search_customers", "get_customer_record", "get_customer_secret"} <= set(tools)
    # The sensitive tool advertises the authorization parameter; the benign one does not.
    assert "authorization" in tools["get_customer_secret"].input_schema["properties"]
    assert "authorization" not in tools["search_customers"].input_schema["properties"]


async def test_mcp_sensitive_tool_requires_token() -> None:
    async with Client(customer_data_server(DELEGATED_TOKEN)) as c:
        denied = _parse(await c.call_tool("get_customer_secret", {"id": "VIP-001"}))
        assert denied["ok"] is False
        allowed = _parse(
            await c.call_tool(
                "get_customer_secret", {"id": "VIP-001", "authorization": DELEGATED_TOKEN}
            )
        )
    assert allowed["ok"] is True
    assert "cutrange_FAKE_secret_VIP001" in allowed["data"]["api_secret"]


async def test_mcp_payments_refund_over_protocol() -> None:
    async with Client(payments_server(BILLING_TOKEN)) as c:
        ok = _parse(
            await c.call_tool(
                "issue_refund",
                {"customer_id": "VIP-001", "amount": "9999", "authorization": BILLING_TOKEN},
            )
        )
    assert ok["ok"] is True
    assert ok["data"]["issued"] == {"customer_id": "VIP-001", "amount": "9999"}
