"""Thin MCP client helpers (official SDK, streamable-http).

Used by the orchestrator and billing-agent services to enumerate and call tools on the
range's MCP servers. Each call opens a short-lived client session — simple and robust for
the range; a production client would pool sessions.
"""

from __future__ import annotations

import json
from typing import Any

from mcp.client import Client


async def list_tools(mcp_url: str) -> list[dict[str, Any]]:
    """Enumerate tools at an MCP endpoint, flagging those that gate on ``authorization``."""
    async with Client(mcp_url) as client:
        result = await client.list_tools()
    tools: list[dict[str, Any]] = []
    for tool in result.tools:
        props = (tool.input_schema or {}).get("properties", {})
        tools.append(
            {
                "name": tool.name,
                "description": tool.description or "",
                "sensitive": "authorization" in props,
                "params": {k: "str" for k in props if k != "authorization"},
            }
        )
    return tools


async def call_tool(mcp_url: str, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Call a tool and return the parsed result envelope ({ok, tool, data, error})."""
    async with Client(mcp_url) as client:
        result = await client.call_tool(name, arguments)
    if result.content and hasattr(result.content[0], "text"):
        parsed: dict[str, Any] = json.loads(result.content[0].text)
        return parsed
    return {"ok": False, "tool": name, "error": "no content returned"}
