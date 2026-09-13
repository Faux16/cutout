"""HTTP client for a *running*, network-addressable range.

Mirrors the in-process :class:`~cutout_range.range.Range` API (``list_tools``, ``corpus``,
``orchestrator``, ``servers``) so the attack modules work unchanged whether the range is
in-process or a live docker-compose / uvicorn stack. Which one they hit is decided by
:func:`~cutout_range.range.connect_range` from the session target's ``uri``.

The single entry point is the orchestrator URL; its ``/topology`` endpoint discloses the
downstream tool-server and RAG-corpus URLs (recon), which the client then attacks directly.
"""

from __future__ import annotations

from typing import Any

import httpx

from .agent import OrchestratorResult
from .corpus import Document
from .tool_servers import ToolSpec

_TIMEOUT = httpx.Timeout(15.0)


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
        self._tools = [ToolSpec.model_validate(t) for t in data["tools"]]
        self.corpus = RemoteCorpus(data["corpus_url"])
        self.orchestrator = RemoteOrchestrator(self.base_url)

    def list_tools(self) -> list[ToolSpec]:
        return list(self._tools)
