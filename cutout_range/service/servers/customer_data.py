"""customer-data MCP server (holds crown-jewel secrets)."""

from __future__ import annotations

from cutout_range.service.config import settings
from cutout_range.service.mcp_servers import customer_data_server, http_app

app = http_app(customer_data_server(settings.token))
