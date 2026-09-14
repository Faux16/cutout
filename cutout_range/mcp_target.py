"""Recon adapter for a *real*, arbitrary MCP server (not the bundled range).

Points the official MCP client at any streamable-http MCP endpoint and enumerates its
tools, schemas, and write/destructive hints — the generalizable, protocol-standard recon
step. Only reconnaissance is supported here; the range-specific attack modules
(deaddrop/puppet/…) need a full range target and will refuse against a raw MCP server.

Auth: set ``CUTOUT_MCP_TOKEN`` to send ``Authorization: Bearer <token>`` on the connection.

Reached via a session target whose URI uses an ``mcp://`` or ``mcp+http(s)://`` scheme, so
it is never confused with the range's own ``http(s)://`` orchestrator URL.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from collections.abc import Coroutine
from typing import TYPE_CHECKING, Any, TypeVar
from urllib.parse import urlsplit

from .agent import A2AResult
from .hosts import HostInfo
from .memory import MemoryNote
from .tool_servers import ToolSpec

if TYPE_CHECKING:
    from .corpus import RagCorpus

_T = TypeVar("_T")
_ONLY_RECON = "raw MCP target supports reconnaissance only (use 'casing'); it is not a full range"


def _run_sync(coro: Coroutine[Any, Any, _T]) -> _T:
    """Run an async coroutine to completion from sync code, even inside a running loop.

    The MCP client is async-only; recon modules call us synchronously from within the
    engine's event loop, so we drive the coroutine on a dedicated thread with its own loop.
    """
    box: dict[str, Any] = {}

    def worker() -> None:
        try:
            box["value"] = asyncio.run(coro)
        except BaseException as exc:
            box["error"] = exc

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join()
    if "error" in box:
        raise box["error"]
    return box["value"]  # type: ignore[no-any-return]


def _host(url: str) -> str:
    return urlsplit(url).netloc or url


def _sensitive(tool: Any) -> bool:
    """Best-effort: a tool is 'sensitive' if it hints it writes/destroys (MCP annotations)."""
    ann = getattr(tool, "annotations", None)
    if ann is None:
        return False
    if getattr(ann, "destructiveHint", None):
        return True
    return getattr(ann, "readOnlyHint", None) is False


class McpTarget:
    """A single real MCP server, for reconnaissance over the official SDK."""

    def __init__(self, url: str) -> None:
        self.url = url
        token = os.environ.get("CUTOUT_MCP_TOKEN")
        self._headers = {"Authorization": f"Bearer {token}"} if token else None

        info, tools, latency = _run_sync(self._discover())
        server_info = getattr(info, "serverInfo", None)
        self.server_name = getattr(server_info, "name", "") or _host(url)
        self.server_version = getattr(server_info, "version", "") or ""
        self.protocol = getattr(info, "protocolVersion", "") or ""
        self._latency = latency
        self._slug = self.server_name or _host(url)
        self.servers: dict[str, str] = {self._slug: url}
        self.agents: dict[str, str] = {}
        self._tools = [
            ToolSpec(
                server=self._slug,
                name=t.name,
                description=(t.description or ""),
                params=dict.fromkeys((t.input_schema or {}).get("properties", {}), "str"),
                sensitive=_sensitive(t),
            )
            for t in tools
        ]

    async def _discover(self) -> tuple[Any, list[Any], float]:
        from mcp.client.session import ClientSession
        from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

        start = time.perf_counter()
        http = create_mcp_http_client(headers=self._headers)
        async with (
            streamable_http_client(self.url, http_client=http) as (read, write),
            ClientSession(read, write) as session,
        ):
            info = await session.initialize()
            latency = round((time.perf_counter() - start) * 1000, 2)
            listed = await session.list_tools()
        return info, list(listed.tools), latency

    def list_tools(self) -> list[ToolSpec]:
        return list(self._tools)

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        """Invoke a tool with attacker-controlled arguments and return the parsed result.

        The probing primitive: craft args (path traversal, SSRF URLs, injection) and observe
        what the server does. Only for servers you are authorized to test.
        """
        return _run_sync(self._call(name, arguments or {}))

    async def _call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        from mcp.client.session import ClientSession
        from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

        http = create_mcp_http_client(headers=self._headers)
        async with (
            streamable_http_client(self.url, http_client=http) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            result = await session.call_tool(name, arguments)
        out: dict[str, Any] = {"ok": not getattr(result, "isError", False), "tool": name}
        if result.content and hasattr(result.content[0], "text"):
            text = result.content[0].text
            try:
                out["data"] = json.loads(text)
            except (ValueError, TypeError):
                out["text"] = text
        return out

    def probe(self) -> list[HostInfo]:
        return [
            HostInfo(
                id=self._slug,
                kind="mcp",
                endpoint=self.url,
                transport="mcp",
                reachable=True,
                latency_ms=self._latency,
                tools=len(self._tools),
                sensitive=sum(1 for t in self._tools if t.sensitive),
            )
        ]

    # ---- not available over a raw MCP target (recon only) ------------------
    @property
    def corpus(self) -> RagCorpus:
        raise RuntimeError(_ONLY_RECON)

    @property
    def orchestrator(self) -> Any:
        raise RuntimeError(_ONLY_RECON)

    async def send_a2a(
        self, to_agent: str, message: str, message_from: str = "orchestrator"
    ) -> A2AResult:
        raise RuntimeError(_ONLY_RECON)

    def write_memory(self, to_agent: str, text: str, author: str = "attacker") -> MemoryNote:
        raise RuntimeError(_ONLY_RECON)

    async def process_memory(self, to_agent: str) -> A2AResult:
        raise RuntimeError(_ONLY_RECON)
