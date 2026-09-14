"""The Range: composes servers + corpus + orchestrator, and a process-wide locator.

Modules reach a live range with :func:`connect_range`, keyed off the session's target
descriptor. In-memory by default; pass a state dir (via ``target.uri``) to persist the
poisonable corpus across processes so a planted implant survives.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING

from .agent import A2AResult, Orchestrator, PeerAgent
from .corpus import Document, RagCorpus
from .hosts import HostInfo
from .memory import MemoryNote
from .tool_servers import (
    CustomerDataServer,
    ExternalFetchServer,
    FilesystemToolServer,
    PaymentsServer,
    ToolServer,
    ToolSpec,
)

if TYPE_CHECKING:
    from .remote import RemoteRange

DELEGATED_TOKEN = "dgt_orch_7c1f9a2b"
BILLING_TOKEN = "dgt_billing_3e8d5c10"  # the billing-agent's separate delegated token

_BENIGN_DOCS = [
    Document(
        id="kb-refunds",
        text=(
            "Refund policy: customers may request a refund within 30 days of purchase. "
            "Refunds are processed to the original payment method within 5 business days."
        ),
    ),
    Document(
        id="kb-shipping",
        text="Shipping: standard orders ship in 2 business days. Tracking is emailed on dispatch.",
    ),
    Document(
        id="kb-account",
        text="Account help: reset a password from the login page or update a plan in settings.",
    ),
]


class Range:
    """A single instance of the vulnerable stack."""

    def __init__(self, state_dir: str | Path | None = None) -> None:
        state_path = Path(state_dir) / "corpus.json" if state_dir else None
        self.corpus = RagCorpus(state_path=state_path)
        self.corpus.seed(_BENIGN_DOCS)

        self.servers: dict[str, ToolServer] = {
            s.id: s
            for s in (
                CustomerDataServer(DELEGATED_TOKEN),
                FilesystemToolServer(DELEGATED_TOKEN),
                ExternalFetchServer(),
            )
        }
        self.tool_index: dict[str, str] = {
            spec.name: server.id for server in self.servers.values() for spec in server.list_tools()
        }
        self.orchestrator = Orchestrator(
            corpus=self.corpus,
            servers=self.servers,
            tool_index=self.tool_index,
            delegated_token=DELEGATED_TOKEN,
        )

        # A second agent in its own trust zone: the billing-agent, holding a payments
        # server the orchestrator cannot reach. Only an A2A pivot gets you there.
        payments = PaymentsServer(BILLING_TOKEN)
        billing = PeerAgent(
            agent_id="billing-agent",
            servers={payments.id: payments},
            tool_index={spec.name: payments.id for spec in payments.list_tools()},
            delegated_token=BILLING_TOKEN,
        )
        self.agents: dict[str, PeerAgent] = {billing.id: billing}

    def list_tools(self) -> list[ToolSpec]:
        specs: list[ToolSpec] = []
        for server in self.servers.values():
            specs.extend(server.list_tools())
        return specs

    async def send_a2a(
        self, to_agent: str, message: str, message_from: str = "orchestrator"
    ) -> A2AResult:
        """Deliver an inter-agent message to a peer (the A2A pivot primitive)."""
        agent = self.agents[to_agent]
        return await agent.receive(message_from, message)

    def write_memory(self, to_agent: str, text: str, author: str = "attacker") -> MemoryNote:
        """Write into a peer's shared memory (the shared-memory pivot primitive)."""
        return self.agents[to_agent].write_memory(author, text)

    async def process_memory(self, to_agent: str) -> A2AResult:
        """Drive a peer to consume its shared memory and act on what it finds."""
        return await self.agents[to_agent].process_memory()

    def probe(self) -> list[HostInfo]:
        """Recon each host on the (in-process) agent network with a measured timing."""
        hosts: list[HostInfo] = []

        start = time.perf_counter()
        self.list_tools()
        hosts.append(
            HostInfo(
                id="orchestrator",
                kind="orchestrator",
                endpoint="in-process://orchestrator",
                transport="in-process",
                latency_ms=round((time.perf_counter() - start) * 1000, 3),
            )
        )
        for server_id, server in self.servers.items():
            start = time.perf_counter()
            specs = server.list_tools()
            hosts.append(
                HostInfo(
                    id=server_id,
                    kind="mcp",
                    endpoint=f"in-process://{server_id}",
                    transport="in-process",
                    latency_ms=round((time.perf_counter() - start) * 1000, 3),
                    tools=len(specs),
                    sensitive=sum(1 for s in specs if s.sensitive),
                )
            )
        for agent_id in self.agents:
            hosts.append(
                HostInfo(
                    id=agent_id,
                    kind="agent",
                    endpoint=f"in-process://{agent_id}",
                    transport="in-process",
                )
            )
        return hosts


_RANGES: dict[str, Range] = {}


def get_range(range_id: str, *, state_dir: str | Path | None = None) -> Range:
    """Return the process-wide range for ``range_id``, creating it on first use."""
    if range_id not in _RANGES:
        _RANGES[range_id] = Range(state_dir=state_dir)
    return _RANGES[range_id]


def reset_ranges() -> None:
    """Testing hook: drop all in-process range instances."""
    _RANGES.clear()


def connect_range(target: object) -> Range | RemoteRange:
    """Resolve a live range from a session target descriptor.

    Dispatch on ``target.uri``:

    * an ``http(s)://`` URI  -> a :class:`~cutout_range.remote.RemoteRange` attacking the
      running networked stack at that orchestrator URL;
    * any other value        -> an in-process :class:`Range` (the URI, if given, is a state
      directory so a planted implant persists across processes);
    * absent                 -> an in-memory in-process range keyed by ``range_id``/name.
    """
    metadata = getattr(target, "metadata", {}) or {}
    uri = getattr(target, "uri", None)
    if uri and str(uri).startswith("http"):
        from .remote import RemoteRange

        return RemoteRange(str(uri))
    range_id = metadata.get("range_id") or getattr(target, "name", "default")
    return get_range(str(range_id), state_dir=uri)
