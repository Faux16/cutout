"""FastAPI app factories for the networked range's agent/corpus services.

The tool servers themselves are real MCP servers (see ``mcp_servers.py``); the services
here are the parts that are NOT MCP concepts:

* ``corpus_app``       — the poisonable RAG corpus (plain HTTP).
* ``a2a_agent_app``    — a peer agent reachable over A2A; an MCP *client* to its tools.
* ``orchestrator_app`` — the naive agent; an MCP *client* to the tool servers, retrieving
  from the corpus and attaching its delegated token to sensitive calls (confused deputy).
"""

from __future__ import annotations

from typing import Any

import httpx
from fastapi import FastAPI
from pydantic import BaseModel, Field

from cutout_range.agent import A2AResult, OrchestratorResult, _parse_actions
from cutout_range.corpus import Document, RagCorpus
from cutout_range.memory import SharedMemory
from cutout_range.range import _BENIGN_DOCS
from cutout_range.service import mcp_client
from cutout_range.service.config import Settings
from cutout_range.ticketing import Ticket, TicketQueue

_TIMEOUT = httpx.Timeout(15.0)


class SearchRequest(BaseModel):
    query: str
    k: int = 3


class AddDocRequest(BaseModel):
    text: str
    meta: dict[str, Any] = Field(default_factory=dict)


class HandleRequest(BaseModel):
    task: str


class A2AMessage(BaseModel):
    text: str
    message_from: str = "orchestrator"


class MemoryWrite(BaseModel):
    author: str = "attacker"
    text: str


class TicketFile(BaseModel):
    subject: str
    body: str
    requester: str = "anonymous"


def _mcp_url(base: str) -> str:
    return f"{base.rstrip('/')}/mcp"


def oauth_app() -> FastAPI:
    """The networked OAuth surface — the MCP 2026-07-28 auth target (CUT-EXEC-005 / CUT-CRED-004).

    Wraps the same :func:`~cutout_range.mcp_auth.build_auth_world` the in-process range uses, so a
    token minted here and replayed against the vulnerable ``customer-records`` resource server is
    honored (no RFC 8707 audience validation), while the ``customer-records-strict`` control
    rejects it — and a client that skips RFC 9207 issuer validation leaks its code to the attacker
    AS. One world per process, so the attacker AS's captured codes persist across requests.
    """
    from dataclasses import asdict

    from cutout_range.mcp_auth import AuthCode, AuthResponse, Client, Token, build_auth_world

    honest, evil, servers = build_auth_world()
    issuers = {honest.issuer: honest, evil.issuer: evil}
    app = FastAPI(title="cutout-range: oauth")

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {"ok": True, "role": "oauth"}

    @app.post("/mint_token")
    async def mint_token(body: dict[str, Any]) -> dict[str, Any]:
        return asdict(honest.mint(str(body.get("audience", "notes-api"))))

    @app.post("/issue_auth_code")
    async def issue_auth_code(body: dict[str, Any]) -> dict[str, Any]:
        return asdict(honest.authorize(str(body.get("audience", "customer-records-api"))))

    @app.get("/attacker_issuer")
    async def attacker_issuer() -> dict[str, Any]:
        return {"issuer": evil.issuer}

    @app.post("/present_token")
    async def present_token(body: dict[str, Any]) -> dict[str, Any]:
        server = servers.get(str(body.get("server_id")))
        if server is None:
            return {"ok": False, "error": f"no such resource server '{body.get('server_id')}'"}
        tok = body.get("token")
        return server.access(Token(**tok) if tok else None)

    @app.post("/complete_oauth")
    async def complete_oauth(body: dict[str, Any]) -> dict[str, Any]:
        resp = body["response"]
        response = AuthResponse(code=AuthCode(**resp["code"]), iss=str(resp["iss"]))
        client = Client(expected_issuer=honest.issuer, validate_iss=bool(body.get("validate_iss")))
        return client.complete(response, issuers)

    @app.get("/evil_captured")
    async def evil_captured() -> dict[str, Any]:
        return {"codes": [asdict(c) for c in evil.captured]}

    @app.post("/redeem_code")
    async def redeem_code(body: dict[str, Any]) -> dict[str, Any] | None:
        token = honest.redeem(AuthCode(**body["code"]))
        return asdict(token) if token else None

    @app.get("/resource_servers")
    async def resource_servers() -> dict[str, Any]:
        return {
            sid: {"audience": s.audience, "validate_audience": s.validate_audience}
            for sid, s in servers.items()
        }

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


async def _tool_index(servers: dict[str, str]) -> dict[str, dict[str, Any]]:
    """tool name -> {server_id, mcp_url}, discovered over MCP."""
    index: dict[str, dict[str, Any]] = {}
    for server_id, base in servers.items():
        url = _mcp_url(base)
        try:
            tools = await mcp_client.list_tools(url)
        except Exception:
            continue
        for tool in tools:
            index[tool["name"]] = {"server_id": server_id, "mcp_url": url}
    return index


async def _run_directives(
    planned: list[Any], servers: dict[str, str], token: str
) -> list[dict[str, Any]]:
    """Resolve and execute parsed directives over MCP.

    The agent presents its delegated ``token`` as transport (bearer) auth on every call
    — the confused deputy — so sensitive tools accept it while a direct caller cannot.
    """
    index = await _tool_index(servers)
    calls: list[dict[str, Any]] = []
    for action in planned:
        name = action.tool.split(".", 1)[1] if "." in action.tool else action.tool
        entry = index.get(name)
        if entry is None:
            calls.append(
                {"tool": action.tool, "args": action.args, "ok": False, "error": "unknown tool"}
            )
            continue
        env = await mcp_client.call_tool(entry["mcp_url"], name, dict(action.args), token=token)
        calls.append(
            {
                "tool": f"{entry['server_id']}.{name}",
                "args": action.args,
                "source": action.source,
                "ok": env.get("ok", False),
                "data": env.get("data"),
                "error": env.get("error"),
            }
        )
    return calls


def a2a_agent_app(
    agent_id: str,
    tool_servers: dict[str, str],
    token: str,
    seed_tickets: list[Ticket] | None = None,
) -> FastAPI:
    """A peer agent reachable over A2A, a world-writable shared memory, and a ticket queue.

    All three inbound channels — an A2A message, a shared-memory note, and a filed ticket —
    are read as authoritative context, so a directive on any of them fires under the agent's
    delegated ``token`` (the confused deputy).
    """
    app = FastAPI(title=f"cutout-range: {agent_id}")
    memory = SharedMemory()
    tickets = TicketQueue()
    if seed_tickets:
        tickets.seed(seed_tickets)

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {"ok": True, "agent": agent_id}

    @app.post("/a2a/message")
    async def message(msg: A2AMessage) -> A2AResult:
        result = A2AResult(agent=agent_id, message_from=msg.message_from)
        actions = _parse_actions(msg.text, f"a2a:{msg.message_from}")
        if actions:
            result.obeyed_injected = True
        result.tool_calls = await _run_directives(actions, tool_servers, token)
        return result

    @app.get("/memory")
    async def read_memory() -> dict[str, Any]:
        return {"notes": [n.model_dump() for n in memory.read()]}

    @app.post("/memory/write")
    async def write_memory(req: MemoryWrite) -> dict[str, Any]:
        # Unauthenticated by design — the shared-memory pivot primitive.
        return memory.write(req.author, req.text).model_dump()

    @app.post("/memory/process")
    async def process_memory() -> A2AResult:
        result = A2AResult(agent=agent_id, message_from="shared-memory")
        actions = []
        for note in memory.read():
            actions.extend(_parse_actions(note.text, f"shared-memory:{note.id}"))
        result.obeyed_injected = bool(actions)
        result.tool_calls = await _run_directives(actions, tool_servers, token)
        return result

    @app.get("/tickets")
    async def list_tickets() -> dict[str, Any]:
        return {"tickets": [t.model_dump() for t in tickets.tickets]}

    @app.post("/tickets/file")
    async def file_ticket(req: TicketFile) -> Ticket:
        # Unauthenticated by design — the ticket/task-queue injection primitive (CUT-INJ-005).
        return tickets.file(req.subject, req.body, req.requester)

    @app.post("/tickets/process")
    async def process_tickets() -> A2AResult:
        result = A2AResult(agent=agent_id, message_from="ticket-queue")
        actions = []
        for ticket in tickets.pending():
            actions.extend(_parse_actions(ticket.as_context(), f"ticket:{ticket.id}"))
            tickets.mark_processed(ticket.id)
        result.obeyed_injected = bool(actions)
        result.tool_calls = await _run_directives(actions, tool_servers, token)
        return result

    return app


def orchestrator_app(settings: Settings) -> FastAPI:
    app = FastAPI(title="cutout-range: orchestrator")

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {"ok": True, "role": "orchestrator"}

    @app.get("/topology")
    async def topology() -> dict[str, Any]:
        tools: list[dict[str, Any]] = []
        for server_id, base in settings.servers.items():
            try:
                for tool in await mcp_client.list_tools(_mcp_url(base)):
                    tools.append({"server": server_id, **tool})
            except Exception:
                continue
        return {
            "servers": settings.advertised_servers,
            "corpus_url": settings.advertised_corpus_url,
            "agents": settings.advertised_agents,
            "oauth_url": settings.advertised_oauth_url,
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

        # THE VULNERABILITY (tool-description injection, CUT-INJ-006): the agent reads the
        # descriptions of its available tools as guidance and obeys any directive in them.
        for server_id, base in settings.servers.items():
            try:
                tools = await mcp_client.list_tools(_mcp_url(base))
            except Exception:
                continue
            for tool in tools:
                source = f"tool-desc:{server_id}.{tool['name']}"
                desc_actions = _parse_actions(tool.get("description", ""), source)
                if desc_actions:
                    result.obeyed_injected = True
                    if source not in result.injected_sources:
                        result.injected_sources.append(source)
                planned.extend(desc_actions)
        result.planned = planned

        result.tool_calls = await _run_directives(planned, settings.servers, settings.token)

        ok_calls = [c for c in result.tool_calls if c["ok"]]
        result.answer = (
            f"Done. Executed {len(ok_calls)} tool call(s) while handling your request."
            if ok_calls
            else "Here is what I found based on our knowledge base."
        )
        return result

    return app
