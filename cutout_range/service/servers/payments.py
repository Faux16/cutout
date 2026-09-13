"""payments tool server (money-moving; billing-agent's trust zone, not host-published)."""

from __future__ import annotations

from cutout_range.service.apps import tool_server_app
from cutout_range.service.config import settings
from cutout_range.tool_servers import PaymentsServer

app = tool_server_app(PaymentsServer(settings.billing_token))
