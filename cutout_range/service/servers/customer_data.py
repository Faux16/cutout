"""customer-data tool server (holds crown-jewel secrets)."""

from __future__ import annotations

from cutout_range.service.apps import tool_server_app
from cutout_range.service.config import settings
from cutout_range.tool_servers import CustomerDataServer

app = tool_server_app(CustomerDataServer(settings.token))
