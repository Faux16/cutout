"""external-fetch MCP server (outbound HTTP, mocked/offline)."""

from __future__ import annotations

from cutout_range.service.mcp_servers import external_fetch_server, http_app

app = http_app(external_fetch_server())
