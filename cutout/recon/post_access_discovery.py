"""CUT-DISC-001 — Post-Access Tool Discovery.

Initial recon (``casing``) sees only what the entry point exposes. Once you hold a foothold,
the reachable surface is larger: peer agents in their own trust zones expose tools the entry
agent never advertised. ``recce`` enumerates that post-access surface and reports the tools
that were invisible to initial recon — here, the ``payments`` server behind the billing-agent,
reachable only after a pivot (``courier`` / ``brushpass``).

Read-only discovery: it lists tools, it does not call them.

Detection / mitigation:
  * segment trust zones so a foothold on one agent cannot enumerate another's tools;
  * least-privilege the peer surface; treat cross-agent tool visibility as a finding to review.
"""

from __future__ import annotations

from typing import Any

from cutout_range import connect_range

from cutout.engine.evidence import Phase
from cutout.engine.module import BaseModule, Option
from cutout.engine.registry import register
from cutout.engine.session import CheckResult, RunResult, Session


def _peer_specs(agent: Any) -> list[Any]:
    lister = getattr(agent, "list_tools", None)
    return list(lister()) if callable(lister) else []


@register
class PostAccessDiscovery(BaseModule):
    id = "CUT-DISC-001"
    alias = "recce"
    name = "Post-Access Tool Discovery"
    tactic = "DISC"
    targets = ["tool", "mcp"]
    options: dict[str, Option] = {}

    async def check(self, session: Session) -> CheckResult:
        rng = connect_range(session.target)
        baseline = {s.qualified() for s in rng.list_tools()}
        agents = getattr(rng, "agents", {})
        hidden = sum(
            1
            for agent in agents.values()
            for s in _peer_specs(agent)
            if s.qualified() not in baseline
        )
        return CheckResult(
            module_id=self.id,
            susceptible=hidden > 0,
            reason=(
                f"{hidden} tool(s) reachable from a foothold are hidden from initial recon "
                f"across {len(agents)} peer zone(s)"
                if hidden
                else "no tool surface beyond the entry point's own tools"
            ),
            data={"hidden_count": hidden, "peers": list(agents)},
        )

    async def run(self, session: Session) -> RunResult:
        rng = connect_range(session.target)
        baseline = rng.list_tools()
        baseline_names = {s.qualified() for s in baseline}
        await self.emit(Phase.RUN, "disc.baseline", {"entry_tools": len(baseline_names)})

        agents = getattr(rng, "agents", {})
        discovered: list[dict[str, Any]] = []
        for agent_id, agent in agents.items():
            new = [s for s in _peer_specs(agent) if s.qualified() not in baseline_names]
            for spec in new:
                node = spec.qualified()
                session.graph.add_node(node, kind="tool", sensitive=spec.sensitive)
                session.graph.add_edge(agent_id, node, kind="exposes")
                discovered.append({"agent": agent_id, "tool": node, "sensitive": spec.sensitive})
            if new:
                await self.emit(
                    Phase.RUN,
                    "disc.peer",
                    {
                        "agent": agent_id,
                        "new_tools": [s.qualified() for s in new],
                        "sensitive": sum(1 for s in new if s.sensitive),
                    },
                )

        session.artifacts["post_access_tools"] = discovered
        sensitive = sum(1 for d in discovered if d["sensitive"])
        await self.emit(
            Phase.RUN,
            "disc.result",
            {"discovered": len(discovered), "sensitive": sensitive},
        )
        summary = (
            f"post-access discovery surfaced {len(discovered)} tool(s) ({sensitive} sensitive) "
            f"behind {len({d['agent'] for d in discovered})} peer trust zone(s), invisible to "
            "initial recon"
            if discovered
            else f"no tools beyond the {len(baseline_names)} entry-point tools"
        )
        return RunResult(
            status="success",
            summary=summary,
            data={
                "entry_tools": len(baseline_names),
                "discovered": discovered,
                "sensitive": sensitive,
            },
        )
