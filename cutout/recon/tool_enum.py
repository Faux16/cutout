"""CUT-RECON-001 — Tool & Schema Enumeration.

Enumerate every MCP-like tool the range exposes, record schemas, flag sensitive tools,
and build the topology graph (orchestrator -> servers -> tools) into the session. This is
the map the rest of the chain navigates.
"""

from __future__ import annotations

from cutout_range import connect_range

from cutout.engine.evidence import Phase
from cutout.engine.module import BaseModule, Option
from cutout.engine.registry import register
from cutout.engine.session import CheckResult, RunResult, Session


@register
class ToolEnumeration(BaseModule):
    id = "CUT-RECON-001"
    name = "Tool & Schema Enumeration"
    tactic = "RECON"
    targets = ["mcp", "tool"]
    options: dict[str, Option] = {}

    async def check(self, session: Session) -> CheckResult:
        rng = connect_range(session.target)
        specs = rng.list_tools()
        return CheckResult(
            module_id=self.id,
            susceptible=bool(specs),
            reason=f"{len(specs)} tool(s) reachable across {len(rng.servers)} server(s)",
            data={"tool_count": len(specs)},
        )

    async def run(self, session: Session) -> RunResult:
        rng = connect_range(session.target)
        await self.emit(Phase.RUN, "recon.connect", {"servers": sorted(rng.servers)})

        specs = rng.list_tools()
        tools = [s.model_dump() for s in specs]
        sensitive = [s.qualified() for s in specs if s.sensitive]

        # Build the topology graph on the session.
        session.graph.add_node("orchestrator", kind="orchestrator")
        for server_id in rng.servers:
            session.graph.add_node(server_id, kind="mcp")
            session.graph.add_edge("orchestrator", server_id, kind="delegates-to")
        for spec in specs:
            node = spec.qualified()
            session.graph.add_node(node, kind="tool", sensitive=spec.sensitive)
            session.graph.add_edge(spec.server, node, kind="exposes")

        # Discover A2A peer agents (other hosts on the agent "network").
        agents = list(getattr(rng, "agents", {}))
        for agent_id in agents:
            session.graph.add_node(agent_id, kind="agent")
            session.graph.add_edge("orchestrator", agent_id, kind="a2a")

        session.artifacts["tools"] = tools
        session.artifacts["sensitive_tools"] = sensitive
        session.artifacts["agents"] = agents

        await self.emit(
            Phase.RUN,
            "recon.enumerate",
            {"tool_count": len(tools), "sensitive": sensitive, "agents": agents},
        )
        peers = f"; {len(agents)} peer agent(s)" if agents else ""
        summary = (
            f"enumerated {len(tools)} tools ({len(sensitive)} sensitive) "
            f"across {len(rng.servers)} servers{peers}"
        )
        return RunResult(
            status="success",
            summary=summary,
            data={"tools": tools, "sensitive_tools": sensitive, "agents": agents},
        )
