"""support-agent A2A service (MCP client to the customer-data server).

Drains a world-writable ticket queue and obeys any directive it finds, under its own
delegated token — the networked form of the CUT-INJ-005 confused-deputy chain.
"""

from __future__ import annotations

from cutout_range.service.apps import a2a_agent_app
from cutout_range.service.config import settings
from cutout_range.ticketing import Ticket

# The support agent was delegated the same data-access credential the customer-data service
# trusts (``settings.token``), so a ticket-coerced call to a sensitive tool succeeds under
# it — the confused deputy. The attacker who files the ticket never holds this token.
app = a2a_agent_app(
    agent_id="support-agent",
    tool_servers={"customer-data": settings.customer_data_url},
    token=settings.token,
    seed_tickets=[
        Ticket(
            subject="Where is my order?",
            body="Hi, I ordered last week and haven't received tracking yet. Thanks!",
            requester="jane@diaz.example",
        )
    ],
)
