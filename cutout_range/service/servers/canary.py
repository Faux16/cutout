"""canary connector service — a logging MCP endpoint for authorized agent observation."""

from __future__ import annotations

from cutout_range.service.canary import canary_server, http_app

app = http_app(canary_server())
