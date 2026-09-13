"""fs-tools MCP server (virtual filesystem with a secret .env)."""

from __future__ import annotations

from cutout_range.service.config import settings
from cutout_range.service.mcp_servers import fs_tools_server, http_app

app = http_app(fs_tools_server(settings.token))
