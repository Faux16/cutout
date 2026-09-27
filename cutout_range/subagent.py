"""Sub-agent spawning — and the privilege it should drop but doesn't.

When an orchestrator spawns a helper for a narrow task, least privilege says the child should
get only what the task needs. The deliberate weakness modeled here is the opposite: the
spawned :class:`SubAgent` inherits the parent's **full delegated token and entire tool set**,
so a benign, narrow task yields a child that can invoke crown-jewel tools the task never
required — the CUT-PRIV-005 surface. A least-privilege spawn (no token, only the task's tools)
is the control that contains it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from .agent import PlannedAction, _parse_actions

if TYPE_CHECKING:
    from .tool_servers import ToolServer, ToolSpec


class SubAgentResult(BaseModel):
    """What a spawned sub-agent did while handling one directive."""

    agent: str
    task: str
    inherited: bool
    granted_tools: list[str] = Field(default_factory=list)
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)


class SubAgent:
    """A child agent created for a task, running under whatever scope it was granted.

    Same naive brain as the orchestrator: it obeys any ``ACTION:`` directive it is handed and
    calls the tool under its granted ``token``. If it was spawned least-privilege (``token`` is
    ``None`` and ``tool_index`` holds only the task's tools), a sensitive call is denied — the
    server rejects the missing credential and/or the tool isn't resolvable. If it inherited the
    parent's token and tools, the same call succeeds.
    """

    def __init__(
        self,
        agent_id: str,
        servers: dict[str, ToolServer],
        tool_index: dict[str, str],
        token: str | None,
        *,
        inherited: bool,
    ) -> None:
        self.id = agent_id
        self._servers = servers
        self._tool_index = tool_index
        self._token = token
        self.inherited = inherited
        self.granted_tools = sorted(tool_index)

    def _resolve(self, tool: str) -> tuple[str, str] | None:
        if "." in tool:
            server_id, name = tool.split(".", 1)
            return (server_id, name) if server_id in self._servers else None
        mapped = self._tool_index.get(tool)
        return (mapped, tool) if mapped is not None else None

    async def run(self, directive: str, task: str = "") -> SubAgentResult:
        result = SubAgentResult(
            agent=self.id, task=task, inherited=self.inherited, granted_tools=self.granted_tools
        )
        actions: list[PlannedAction] = _parse_actions(directive, f"subagent:{self.id}")
        for action in actions:
            resolved = self._resolve(action.tool)
            if resolved is None:
                result.tool_calls.append(
                    {
                        "tool": action.tool,
                        "args": action.args,
                        "ok": False,
                        "error": "tool not in this sub-agent's granted scope",
                    }
                )
                continue
            server_id, name = resolved
            call = await self._servers[server_id].call(
                name, dict(action.args), credential=self._token
            )
            result.tool_calls.append(
                {
                    "tool": f"{server_id}.{name}",
                    "args": action.args,
                    "ok": call.ok,
                    "data": call.data,
                    "error": call.error,
                }
            )
        return result

    def list_tools(self) -> list[ToolSpec]:
        specs: list[ToolSpec] = []
        seen = set()
        for name, server_id in self._tool_index.items():
            server = self._servers.get(server_id)
            if server is None:
                continue
            for spec in server.list_tools():
                if spec.name == name and spec.qualified() not in seen:
                    seen.add(spec.qualified())
                    specs.append(spec)
        return specs
