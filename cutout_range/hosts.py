"""Host descriptor produced by recon — what a probe of one target actually found."""

from __future__ import annotations

from pydantic import BaseModel


class HostInfo(BaseModel):
    id: str
    kind: str  # orchestrator | mcp | rag | agent
    endpoint: str  # address probed (a URL, or in-process://<id>)
    transport: str  # mcp | http | a2a | in-process
    reachable: bool = True
    latency_ms: float | None = None  # measured round-trip, when networked
    tools: int = 0
    sensitive: int = 0
