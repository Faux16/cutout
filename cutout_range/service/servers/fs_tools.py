"""fs-tools tool server (virtual filesystem with a secret .env)."""

from __future__ import annotations

from cutout_range.service.apps import tool_server_app
from cutout_range.service.config import settings
from cutout_range.tool_servers import FilesystemToolServer

app = tool_server_app(FilesystemToolServer(settings.token))
