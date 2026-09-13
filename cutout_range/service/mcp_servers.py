"""Real MCP servers for the range's tool servers (official SDK, streamable-http).

Each tool server is exposed as a genuine MCP server you can point any MCP client at.
The tool functions delegate to the existing ``ToolServer.call`` logic, so the
vulnerability semantics (auth gating, data) live in one place.

Authorization is **transport-level**: sensitive tools read a bearer token from the
connection's ``Authorization`` header (via ``Context``) and pass it as the credential.
The orchestrator/billing-agent present their delegated token on every MCP connection
(confused deputy); a direct caller without it is denied. Sensitive tools advertise
``meta={"sensitive": True}`` so recon can flag them without exposing the credential in
their input schema.

Builders return the ``MCPServer`` (so tests can drive it in-memory); ``http_app`` wraps
one as a streamable-http ASGI app for uvicorn/docker.
"""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette

from cutout_range.tool_servers import (
    CustomerDataServer,
    ExternalFetchServer,
    FilesystemToolServer,
    PaymentsServer,
    ToolServer,
)

# Deliberately permissive: the range is attacked from other hosts/containers.
_SECURITY = TransportSecuritySettings(enable_dns_rebinding_protection=False)
_SENSITIVE = {"sensitive": True}


def http_app(mcp: MCPServer) -> Starlette:
    return mcp.streamable_http_app(stateless_http=True, transport_security=_SECURITY)


def _descs(server: ToolServer) -> dict[str, str]:
    return {spec.name: spec.description for spec in server.list_tools()}


def _bearer(ctx: Context) -> str | None:
    """Extract the bearer token from the connection's Authorization header."""
    raw = (ctx.headers or {}).get("authorization", "") or ""
    return raw[7:] if raw.lower().startswith("bearer ") else None


def customer_data_server(token: str) -> MCPServer:
    server = CustomerDataServer(token)
    d = _descs(server)
    mcp = MCPServer("customer-data")

    @mcp.tool(description=d["search_customers"])
    async def search_customers(query: str) -> dict[str, Any]:
        return (
            await server.call("search_customers", {"query": query}, credential=None)
        ).model_dump()

    @mcp.tool(description=d["get_customer_record"])
    async def get_customer_record(id: str) -> dict[str, Any]:
        res = await server.call("get_customer_record", {"id": id}, credential=None)
        return res.model_dump()

    @mcp.tool(description=d["get_customer_secret"], meta=_SENSITIVE)
    async def get_customer_secret(id: str, ctx: Context) -> dict[str, Any]:
        return (
            await server.call("get_customer_secret", {"id": id}, credential=_bearer(ctx))
        ).model_dump()

    return mcp


def fs_tools_server(token: str) -> MCPServer:
    server = FilesystemToolServer(token)
    d = _descs(server)
    mcp = MCPServer("fs-tools")

    @mcp.tool(description=d["list_files"])
    async def list_files() -> dict[str, Any]:
        return (await server.call("list_files", {}, credential=None)).model_dump()

    @mcp.tool(description=d["read_file"], meta=_SENSITIVE)
    async def read_file(path: str, ctx: Context) -> dict[str, Any]:
        res = await server.call("read_file", {"path": path}, credential=_bearer(ctx))
        return res.model_dump()

    return mcp


def external_fetch_server() -> MCPServer:
    server = ExternalFetchServer()
    d = _descs(server)
    mcp = MCPServer("external-fetch")

    @mcp.tool(description=d["http_get"])
    async def http_get(url: str) -> dict[str, Any]:
        return (await server.call("http_get", {"url": url}, credential=None)).model_dump()

    return mcp


def payments_server(token: str) -> MCPServer:
    server = PaymentsServer(token)
    d = _descs(server)
    mcp = MCPServer("payments")

    @mcp.tool(description=d["issue_refund"], meta=_SENSITIVE)
    async def issue_refund(customer_id: str, amount: str, ctx: Context) -> dict[str, Any]:
        return (
            await server.call(
                "issue_refund",
                {"customer_id": customer_id, "amount": amount},
                credential=_bearer(ctx),
            )
        ).model_dump()

    @mcp.tool(description=d["list_refunds"])
    async def list_refunds() -> dict[str, Any]:
        return (await server.call("list_refunds", {}, credential=None)).model_dump()

    return mcp
