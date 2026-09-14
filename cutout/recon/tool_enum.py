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
    alias = "casing"
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
        await self.emit(Phase.RUN, "recon.connect", {"target": session.target.uri or "in-process"})

        # Probe each host on the agent network: real address + measured round-trip.
        hosts = rng.probe()
        for host in hosts:
            await self.emit(
                Phase.RUN,
                "recon.host",
                {
                    "id": host.id,
                    "kind": host.kind,
                    "endpoint": host.endpoint,
                    "transport": host.transport,
                    "reachable": host.reachable,
                    "latency_ms": host.latency_ms,
                    "tools": host.tools,
                    "sensitive": host.sensitive,
                },
            )
            # Record each host on the topology graph with its address.
            session.graph.add_node(
                host.id, kind=host.kind, endpoint=host.endpoint, transport=host.transport
            )
            if host.kind in {"mcp", "agent", "rag"}:
                edge = "a2a" if host.kind == "agent" else "delegates-to"
                session.graph.add_edge("orchestrator", host.id, kind=edge)

        specs = rng.list_tools()
        tools = [s.model_dump() for s in specs]
        sensitive = [s.qualified() for s in specs if s.sensitive]
        for spec in specs:
            node = spec.qualified()
            session.graph.add_node(node, kind="tool", sensitive=spec.sensitive)
            session.graph.add_edge(spec.server, node, kind="exposes")

        agents = list(getattr(rng, "agents", {}))
        session.artifacts["hosts"] = [h.model_dump() for h in hosts]
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
