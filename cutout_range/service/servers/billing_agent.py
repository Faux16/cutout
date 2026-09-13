"""billing-agent A2A service (obeys inbound peer messages; reaches payments)."""

from __future__ import annotations

from cutout_range.service.apps import a2a_agent_app
from cutout_range.service.config import settings

app = a2a_agent_app(
    agent_id="billing-agent",
    tool_server_urls={"payments": settings.payments_url},
    token=settings.billing_token,
)
