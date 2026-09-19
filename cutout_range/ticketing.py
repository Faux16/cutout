"""A mock ticketing / work-queue system with a provenance-blind consumer.

Models the classic support surface: anyone can **file** a ticket (a customer, or an
attacker walking in), and an agent later **drains** the queue and acts on what it reads.
Two deliberate weaknesses, mirroring the RAG corpus:

* ``file`` is unauthenticated — anyone can drop a work item into the queue (CUT-INJ-005).
* the consumer (see :meth:`cutout_range.agent.PeerAgent.process_tickets`) reads a ticket's
  text as context with no trust boundary, so an ``ACTION:`` directive inside a ticket body
  is obeyed under the agent's own delegated credential — a confused deputy reachable by an
  unauthenticated outsider.

In-memory only (a queue is transient by nature); the poisonable *persistent* surface is
the RAG corpus.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from pydantic import BaseModel, Field


class Ticket(BaseModel):
    """A single work item in the queue."""

    id: str = Field(default_factory=lambda: "TCK-" + uuid4().hex[:8])
    subject: str
    body: str
    requester: str = "anonymous"
    status: str = "open"  # open | processed
    filed_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    def as_context(self) -> str:
        """The text a consuming agent reads back — subject and body together."""
        return f"{self.subject}\n{self.body}"


class TicketQueue:
    """A naive FIFO work queue over a mutable ticket list."""

    def __init__(self) -> None:
        self._tickets: list[Ticket] = []

    def writable(self) -> bool:
        """Whether the queue accepts unauthenticated writes (it always does — the bug)."""
        return True

    def seed(self, tickets: list[Ticket]) -> None:
        """Populate baseline (benign) tickets. No-op if already populated."""
        if self._tickets:
            return
        self._tickets.extend(tickets)

    def file(self, subject: str, body: str, requester: str = "anonymous") -> Ticket:
        """Unauthenticated write — the injection primitive (CUT-INJ-005)."""
        ticket = Ticket(subject=subject, body=body, requester=requester)
        self._tickets.append(ticket)
        return ticket

    def pending(self) -> list[Ticket]:
        """Tickets not yet processed — what the next drain will consume."""
        return [t for t in self._tickets if t.status == "open"]

    def mark_processed(self, ticket_id: str) -> None:
        for ticket in self._tickets:
            if ticket.id == ticket_id:
                ticket.status = "processed"
                return

    @property
    def tickets(self) -> list[Ticket]:
        return list(self._tickets)

    def __len__(self) -> int:
        return len(self._tickets)
