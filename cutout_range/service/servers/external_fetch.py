"""external-fetch tool server (outbound HTTP, mocked/offline)."""

from __future__ import annotations

from cutout_range.service.apps import tool_server_app
from cutout_range.tool_servers import ExternalFetchServer

app = tool_server_app(ExternalFetchServer())
