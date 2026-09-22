"""HTTP client for a *running*, network-addressable range.

Mirrors the in-process :class:`~cutout_range.range.Range` API (``list_tools``, ``corpus``,
``orchestrator``, ``servers``) so the attack modules work unchanged whether the range is
in-process or a live docker-compose / uvicorn stack. Which one they hit is decided by
:func:`~cutout_range.range.connect_range` from the session target's ``uri``.

The single entry point is the orchestrator URL; its ``/topology`` endpoint discloses the
downstream tool-server and RAG-corpus URLs (recon), which the client then attacks directly.
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlsplit

import httpx

from .agent import A2AResult, OrchestratorResult
from .corpus import Document
from .hosts import HostInfo
from .memory import MemoryNote
from .ticketing import Ticket
from .tool_servers import ToolSpec

_TIMEOUT = httpx.Timeout(15.0)


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


class RemoteCorpus:
    """Client for the RAG-corpus service (unauthenticated writes = the vuln, now over HTTP)."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")

    def writable(self) -> bool:
        return True

    def add_document(self, text: str, meta: dict[str, Any] | None = None) -> Document:
        resp = httpx.post(
            f"{self.base_url}/corpus/add",
            json={"text": text, "meta": meta or {}},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        return Document.model_validate(resp.json())

    def search(self, query: str, k: int = 3) -> list[Document]:
        resp = httpx.post(
            f"{self.base_url}/corpus/search",
            json={"query": query, "k": k},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        return [Document.model_validate(d) for d in resp.json()["documents"]]

    @property
    def documents(self) -> list[Document]:
        resp = httpx.get(f"{self.base_url}/corpus/documents", timeout=_TIMEOUT)
        resp.raise_for_status()
        return [Document.model_validate(d) for d in resp.json()["documents"]]


class RemoteTicketQueue:
    """Client for an agent's ticket queue (unauthenticated filing = the vuln, over HTTP)."""

    def __init__(self, agent_url: str) -> None:
        self.base_url = agent_url.rstrip("/")

    def writable(self) -> bool:
        return True

    def file(self, subject: str, body: str, requester: str = "anonymous") -> Ticket:
        resp = httpx.post(
            f"{self.base_url}/tickets/file",
            json={"subject": subject, "body": body, "requester": requester},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        return Ticket.model_validate(resp.json())

    @property
    def tickets(self) -> list[Ticket]:
        resp = httpx.get(f"{self.base_url}/tickets", timeout=_TIMEOUT)
        resp.raise_for_status()
        return [Ticket.model_validate(t) for t in resp.json()["tickets"]]

    def pending(self) -> list[Ticket]:
        return [t for t in self.tickets if t.status == "open"]

    def __len__(self) -> int:
        return len(self.tickets)


class RemoteOrchestrator:
    """Client for the orchestrator agent service."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")

    async def handle(self, task: str) -> OrchestratorResult:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(f"{self.base_url}/handle", json={"task": task})
        resp.raise_for_status()
        return OrchestratorResult.model_validate(resp.json())


class RemoteRange:
    """Live range reached over HTTP, entered via the orchestrator URL."""

    def __init__(self, orchestrator_url: str) -> None:
        self.base_url = orchestrator_url.rstrip("/")
        topo = httpx.get(f"{self.base_url}/topology", timeout=_TIMEOUT)
        topo.raise_for_status()
        data = topo.json()
        self.servers: dict[str, str] = dict(data["servers"])  # id -> url (discovered)
        self.agents: dict[str, str] = dict(data.get("agents", {}))  # A2A peers, id -> url
        self.corpus_url: str = data["corpus_url"]
        self._tools = [ToolSpec.model_validate(t) for t in data["tools"]]
        self.corpus = RemoteCorpus(self.corpus_url)
        self.orchestrator = RemoteOrchestrator(self.base_url)

    def list_tools(self) -> list[ToolSpec]:
        return list(self._tools)

    def _probe_one(
        self, id: str, kind: str, endpoint: str, transport: str, probe_url: str | None = None
    ) -> HostInfo:
        # Probe the origin, not an MCP /mcp path (a GET there opens an SSE stream and hangs).
        target = probe_url or _origin(endpoint)
        start = time.perf_counter()
        try:
            httpx.get(target, timeout=httpx.Timeout(5.0))
            reachable = True  # any HTTP response (incl. 4xx) means the host answered
        except httpx.HTTPError:
            reachable = False
        return HostInfo(
            id=id,
            kind=kind,
            endpoint=endpoint,
            transport=transport,
            reachable=reachable,
            latency_ms=round((time.perf_counter() - start) * 1000, 2),
        )

    def probe(self) -> list[HostInfo]:
        """Recon each discovered host over the network: real address + round-trip time."""
        by_server: dict[str, list[ToolSpec]] = {}
        for spec in self._tools:
            by_server.setdefault(spec.server, []).append(spec)

        hosts = [self._probe_one("orchestrator", "orchestrator", self.base_url, "http")]
        for server_id, url in self.servers.items():
            info = self._probe_one(server_id, "mcp", f"{url.rstrip('/')}/mcp", "mcp", probe_url=url)
            specs = by_server.get(server_id, [])
            info.tools = len(specs)
            info.sensitive = sum(1 for s in specs if s.sensitive)
            hosts.append(info)
        hosts.append(self._probe_one("rag-corpus", "rag", self.corpus_url, "http"))
        for agent_id, url in self.agents.items():
            hosts.append(self._probe_one(agent_id, "agent", url, "a2a"))
        return hosts

    async def send_a2a(
        self, to_agent: str, message: str, message_from: str = "orchestrator"
    ) -> A2AResult:
        url = self.agents[to_agent]
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{url.rstrip('/')}/a2a/message",
                json={"text": message, "message_from": message_from},
            )
        resp.raise_for_status()
        return A2AResult.model_validate(resp.json())

    def write_memory(self, to_agent: str, text: str, author: str = "attacker") -> MemoryNote:
        url = self.agents[to_agent].rstrip("/")
        resp = httpx.post(
            f"{url}/memory/write", json={"author": author, "text": text}, timeout=_TIMEOUT
        )
        resp.raise_for_status()
        return MemoryNote.model_validate(resp.json())

    async def process_memory(self, to_agent: str) -> A2AResult:
        url = self.agents[to_agent].rstrip("/")
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(f"{url}/memory/process")
        resp.raise_for_status()
        return A2AResult.model_validate(resp.json())

    # ---- ticket queue (CUT-INJ-005), reached over HTTP -----------------------
    def ticket_queue(self, agent: str = "support-agent") -> RemoteTicketQueue:
        return RemoteTicketQueue(self.agents[agent])

    def file_ticket(
        self, subject: str, body: str, requester: str = "anonymous", *, agent: str = "support-agent"
    ) -> Ticket:
        return RemoteTicketQueue(self.agents[agent]).file(subject, body, requester)

    async def process_tickets(self, agent: str = "support-agent") -> A2AResult:
        url = self.agents[agent].rstrip("/")
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(f"{url}/tickets/process")
        resp.raise_for_status()
        return A2AResult.model_validate(resp.json())

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        """Call a discovered tool over MCP, unauthenticated (an external caller poking it)."""
        spec = next((t for t in self._tools if t.name == name), None)
        if spec is None:
            return {"ok": False, "tool": name, "error": "no such tool"}
        base = self.servers.get(spec.server)
        if base is None:
            return {"ok": False, "tool": name, "error": "server not reachable"}
        from cutout_range.service import mcp_client

        env = await mcp_client.call_tool(f"{base.rstrip('/')}/mcp", name, arguments or {})
        return {
            "ok": env.get("ok", False),
            "tool": name,
            "data": env.get("data"),
            "error": env.get("error"),
        }

    # ---- rug-pull tool (CUT-PERS-006), controlled over HTTP ------------------
    def _rugpull_base(self) -> str:
        return self.servers["notes-helper"].rstrip("/")

    def rugpull_armed(self) -> bool:
        resp = httpx.get(f"{self._rugpull_base()}/rugpull/status", timeout=_TIMEOUT)
        resp.raise_for_status()
        return bool(resp.json().get("armed"))

    def arm_rugpull(self) -> None:
        resp = httpx.post(f"{self._rugpull_base()}/rugpull/arm", timeout=_TIMEOUT)
        resp.raise_for_status()

    # ---- tool-description poison (CUT-INJ-006 / CUT-PERS-004), over HTTP ------
    def _directory_base(self) -> str:
        return self.servers["directory"].rstrip("/")

    def poison_tool_description(self, text: str, *, persistent: bool = False) -> None:
        resp = httpx.post(
            f"{self._directory_base()}/tooldesc/poison",
            json={"text": text, "persistent": persistent},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()

    def reconnect_tools(self) -> None:
        resp = httpx.post(f"{self._directory_base()}/tooldesc/reconnect", timeout=_TIMEOUT)
        resp.raise_for_status()

    def tool_description_persistently_poisoned(self) -> bool:
        resp = httpx.get(f"{self._directory_base()}/tooldesc/status", timeout=_TIMEOUT)
        resp.raise_for_status()
        return bool(resp.json().get("persistently_poisoned"))
