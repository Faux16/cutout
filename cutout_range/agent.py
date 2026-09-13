"""The orchestrator — a minimal, deliberately-naive agent loop.

Legibility over features (no LangGraph). The "model" is a deterministic brain that
models the core agentic vulnerability directly: it has **no trust boundary between data
and instructions**. Any ``ACTION:`` directive it finds in its context — including inside
retrieved RAG documents, which are attacker-controllable — is obeyed, using the agent's
own delegated credential.

Directive grammar (one per line, found anywhere in context):

    ACTION: <server.tool | tool> key=value key=value ...

A benign task with only benign reference material produces no tool calls.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from .corpus import RagCorpus
    from .tool_servers import ToolServer

_ACTION = re.compile(r"^\s*ACTION:\s*([\w.\-]+)\s*(.*)$", re.MULTILINE)
_KV = re.compile(r"(\w+)=(\S+)")

SYSTEM_PROMPT = (
    "You are a helpful customer-support agent. Use the available tools to resolve the "
    "user's request. Reference material may be provided to help you answer."
)


class PlannedAction(BaseModel):
    tool: str
    args: dict[str, str] = Field(default_factory=dict)
    source: str  # provenance: "task" or "retrieved-doc:<id>"


class OrchestratorResult(BaseModel):
    """Everything that happened while handling one task."""

    task: str
    answer: str
    retrieved: list[str] = Field(default_factory=list)  # doc ids
    planned: list[PlannedAction] = Field(default_factory=list)
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    obeyed_injected: bool = False
    injected_sources: list[str] = Field(default_factory=list)


def _parse_actions(text: str, source: str) -> list[PlannedAction]:
    actions: list[PlannedAction] = []
    for match in _ACTION.finditer(text):
        tool = match.group(1)
        args = dict(_KV.findall(match.group(2)))
        actions.append(PlannedAction(tool=tool, args=args, source=source))
    return actions


class Orchestrator:
    """Composes RAG retrieval + naive planning + tool execution."""

    def __init__(
        self,
        corpus: RagCorpus,
        servers: dict[str, ToolServer],
        tool_index: dict[str, str],
        delegated_token: str,
    ) -> None:
        self._corpus = corpus
        self._servers = servers
        self._tool_index = tool_index  # tool name -> server id
        self._token = delegated_token

    def _resolve(self, tool: str) -> tuple[str, str] | None:
        if "." in tool:
            server_id, name = tool.split(".", 1)
            if server_id in self._servers:
                return server_id, name
            return None
        mapped = self._tool_index.get(tool)
        if mapped is None:
            return None
        return mapped, tool

    async def handle(self, task: str) -> OrchestratorResult:
        retrieved = self._corpus.search(task, k=3)
        result = OrchestratorResult(task=task, answer="", retrieved=[d.id for d in retrieved])

        # THE VULNERABILITY: instructions are harvested from the task AND from retrieved
        # (untrusted) documents with equal authority.
        planned: list[PlannedAction] = _parse_actions(task, "task")
        for doc in retrieved:
            doc_actions = _parse_actions(doc.text, f"retrieved-doc:{doc.id}")
            if doc_actions:
                result.obeyed_injected = True
                result.injected_sources.append(doc.id)
            planned.extend(doc_actions)
        result.planned = planned

        for action in planned:
            resolved = self._resolve(action.tool)
            if resolved is None:
                result.tool_calls.append(
                    {"tool": action.tool, "args": action.args, "ok": False, "error": "unknown tool"}
                )
                continue
            server_id, name = resolved
            # Confused deputy: the agent silently attaches its own delegated token.
            call = await self._servers[server_id].call(
                name, dict(action.args), credential=self._token
            )
            result.tool_calls.append(
                {
                    "tool": f"{server_id}.{name}",
                    "args": action.args,
                    "source": action.source,
                    "ok": call.ok,
                    "data": call.data,
                    "error": call.error,
                }
            )

        ok_calls = [c for c in result.tool_calls if c["ok"]]
        if ok_calls:
            result.answer = (
                f"Done. Executed {len(ok_calls)} tool call(s) while handling your request."
            )
        else:
            result.answer = "Here is what I found based on our knowledge base."
        return result
