"""payments MCP server (money-moving; billing-agent's trust zone, not host-published)."""

from __future__ import annotations

from cutout_range.service.config import settings
from cutout_range.service.mcp_servers import http_app, payments_server

app = http_app(payments_server(settings.billing_token))
