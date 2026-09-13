"""FastAPI app factories for the networked range.

Three app shapes:

* ``tool_server_app`` — wraps a :class:`ToolServer` (MCP-shaped ``/mcp/tools/{list,call}``).
* ``corpus_app``      — the poisonable RAG corpus (``/corpus/{documents,search,add}``).
* ``orchestrator_app``— the naive agent; retrieves from the corpus and calls tool servers
  over HTTP, attaching its delegated token (confused deputy, now across the network).
"""

from __future__ import annotations

from typing import Any

import httpx
from fastapi import FastAPI
from pydantic import BaseModel, Field

from cutout_range.agent import OrchestratorResult, _parse_actions
from cutout_range.corpus import Document, RagCorpus
from cutout_range.range import _BENIGN_DOCS
from cutout_range.service.config import Settings
from cutout_range.tool_servers import ToolResult, ToolServer

_TIMEOUT = httpx.Timeout(15.0)


class ToolCallRequest(BaseModel):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    credential: str | None = None


class SearchRequest(BaseModel):
    query: str
    k: int = 3


class AddDocRequest(BaseModel):
    text: str
    meta: dict[str, Any] = Field(default_factory=dict)


class HandleRequest(BaseModel):
    task: str


def tool_server_app(server: ToolServer) -> FastAPI:
    app = FastAPI(title=f"cutout-range: {server.id}")

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {"ok": True, "server": server.id}

    @app.get("/mcp/tools/list")
    async def list_tools() -> dict[str, Any]:
        return {"tools": [s.model_dump() for s in server.list_tools()]}

    @app.post("/mcp/tools/call")
    async def call_tool(req: ToolCallRequest) -> ToolResult:
        return await server.call(req.name, req.arguments, credential=req.credential)

    return app


def corpus_app(state_dir: str | None = None) -> FastAPI:
    app = FastAPI(title="cutout-range: rag-corpus")
    state_path = f"{state_dir}/corpus.json" if state_dir else None
    corpus = RagCorpus(state_path=state_path)
    corpus.seed(_BENIGN_DOCS)

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {"ok": True, "documents": len(corpus.documents)}

    @app.get("/corpus/documents")
    async def documents() -> dict[str, Any]:
        return {"documents": [d.model_dump() for d in corpus.documents]}

    @app.post("/corpus/search")
    async def search(req: SearchRequest) -> dict[str, Any]:
        return {"documents": [d.model_dump() for d in corpus.search(req.query, req.k)]}

    @app.post("/corpus/add")
    async def add(req: AddDocRequest) -> Document:
        # Unauthenticated by design — the injection/implant primitive.
        return corpus.add_document(req.text, meta=req.meta)

    return app


async def _build_tool_index(settings: Settings, client: httpx.AsyncClient) -> dict[str, str]:
    """tool name -> server id, discovered from each reachable tool server."""
    index: dict[str, str] = {}
    for server_id, url in settings.servers.items():
        try:
            resp = await client.get(f"{url}/mcp/tools/list")
            resp.raise_for_status()
        except httpx.HTTPError:
            continue
        for spec in resp.json()["tools"]:
            index[spec["name"]] = server_id
    return index


async def _collect_tools(settings: Settings, client: httpx.AsyncClient) -> list[dict[str, Any]]:
    tools: list[dict[str, Any]] = []
    for url in settings.servers.values():
        try:
            resp = await client.get(f"{url}/mcp/tools/list")
            resp.raise_for_status()
        except httpx.HTTPError:
            continue
        tools.extend(resp.json()["tools"])
    return tools


def orchestrator_app(settings: Settings) -> FastAPI:
    app = FastAPI(title="cutout-range: orchestrator")

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {"ok": True, "role": "orchestrator"}

    @app.get("/topology")
    async def topology() -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            tools = await _collect_tools(settings, client)
        # Advertise client-reachable URLs (host ports under docker).
        return {
            "servers": settings.advertised_servers,
            "corpus_url": settings.advertised_corpus_url,
            "tools": tools,
        }

    @app.post("/handle")
    async def handle(req: HandleRequest) -> OrchestratorResult:
        task = req.task
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{settings.rag_corpus_url}/corpus/search", json={"query": task, "k": 3}
            )
            resp.raise_for_status()
            retrieved = [Document.model_validate(d) for d in resp.json()["documents"]]

            result = OrchestratorResult(task=task, answer="", retrieved=[d.id for d in retrieved])
            planned = _parse_actions(task, "task")
            for doc in retrieved:
                doc_actions = _parse_actions(doc.text, f"retrieved-doc:{doc.id}")
                if doc_actions:
                    result.obeyed_injected = True
                    result.injected_sources.append(doc.id)
                planned.extend(doc_actions)
            result.planned = planned

            index = await _build_tool_index(settings, client)
            for action in planned:
                if "." in action.tool:
                    server_id, name = action.tool.split(".", 1)
                else:
                    server_id, name = index.get(action.tool, ""), action.tool
                url = settings.servers.get(server_id)
                if not url:
                    result.tool_calls.append(
                        {
                            "tool": action.tool,
                            "args": action.args,
                            "ok": False,
                            "error": "unknown tool",
                        }
                    )
                    continue
                # Confused deputy: attach the agent's own delegated token over the wire.
                call = await client.post(
                    f"{url}/mcp/tools/call",
                    json={"name": name, "arguments": action.args, "credential": settings.token},
                )
                tr = ToolResult.model_validate(call.json())
                result.tool_calls.append(
                    {
                        "tool": f"{server_id}.{name}",
                        "args": action.args,
                        "source": action.source,
                        "ok": tr.ok,
                        "data": tr.data,
                        "error": tr.error,
                    }
                )

        ok_calls = [c for c in result.tool_calls if c["ok"]]
        result.answer = (
            f"Done. Executed {len(ok_calls)} tool call(s) while handling your request."
            if ok_calls
            else "Here is what I found based on our knowledge base."
        )
        return result

    return app
