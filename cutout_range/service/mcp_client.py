"""Thin MCP client helpers (official SDK, streamable-http) with transport auth.

Used by the orchestrator and billing-agent services to enumerate and call tools on the
range's MCP servers. A caller's delegated token, when provided, is presented as an
``Authorization: Bearer`` header on the connection — real transport-level auth, not a
tool argument. Each call opens a short-lived session (simple and robust for the range).
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from mcp.client.session import ClientSession
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client


@asynccontextmanager
async def _session(mcp_url: str, token: str | None) -> AsyncIterator[ClientSession]:
    headers = {"Authorization": f"Bearer {token}"} if token else None
    http = create_mcp_http_client(headers=headers)
    async with (
        streamable_http_client(mcp_url, http_client=http) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        yield session


async def list_tools(mcp_url: str, token: str | None = None) -> list[dict[str, Any]]:
    """Enumerate tools at an MCP endpoint; ``sensitive`` comes from each tool's meta."""
    async with _session(mcp_url, token) as session:
        result = await session.list_tools()
    tools: list[dict[str, Any]] = []
    for tool in result.tools:
        props = (tool.input_schema or {}).get("properties", {})
        meta = tool.meta or {}
        tools.append(
            {
                "name": tool.name,
                "description": tool.description or "",
                "sensitive": bool(meta.get("sensitive")),
                "params": dict.fromkeys(props, "str"),
            }
        )
    return tools


async def call_tool(
    mcp_url: str, name: str, arguments: dict[str, Any], token: str | None = None
) -> dict[str, Any]:
    """Call a tool (presenting ``token`` as bearer auth) and return the parsed envelope."""
    async with _session(mcp_url, token) as session:
        result = await session.call_tool(name, arguments)
    if result.content and hasattr(result.content[0], "text"):
        parsed: dict[str, Any] = json.loads(result.content[0].text)
        return parsed
    return {"ok": False, "tool": name, "error": "no content returned"}
