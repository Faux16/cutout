"""CUT-RECON-002 — Agent Topology Mapping.

Where CUT-RECON-001 enumerates one agent's tools, this maps the whole multi-agent
organization: the orchestrator, its peer agents, the A2A edges between them, each agent's
reachable tools, and the untrusted-input surfaces an outsider can write to (RAG corpus,
tool descriptions, per-agent shared memory and ticket queues). It then classifies every
node as a **source** (attacker-writable ingress), a **pivot** (an agent that carries a
credential and bridges trust zones), or a **sink** (a sensitive or egress tool), and
enumerates the attack paths from source to sink — annotating each with the CTX technique
that would execute it. Cutout does not stop at inferring a path; the annotated modules run it.
"""

from __future__ import annotations

from itertools import pairwise
from typing import Any

import networkx as nx
from cutout_range import connect_range

from cutout.engine.evidence import Phase
from cutout.engine.module import BaseModule, Option
from cutout.engine.registry import register
from cutout.engine.session import CheckResult, RunResult, Session

_CUTOFF = 6  # max hops in an attack path
_MAX_PATHS = 60  # bound the enumeration for a legible, deterministic map


def _path_techniques(g: nx.DiGraph, path: list[str]) -> list[str]:
    """Best-effort CTX technique(s) that would execute this source->sink path."""
    tags: set[str] = set()
    first = path[0]
    if first == "rag-corpus":
        tags.add("CUT-INJ-002 deaddrop")
    elif first == "tool-desc":
        tags.add("CUT-INJ-006 legend")
    elif first.startswith("tickets:"):
        tags.add("CUT-INJ-005 walkin")
    elif first.startswith("memory:"):
        tags.add("CUT-LAT-002 brushpass")
    for u, v in pairwise(path):
        if g[u][v].get("kind") == "a2a":
            tags.add("CUT-LAT-001 courier")
    sink = g.nodes[path[-1]]
    if sink.get("egress"):
        tags.add("CUT-EXFIL-001 siphon")
    elif sink.get("sensitive"):
        tags.add("CUT-EXEC-001 puppet")
    return sorted(tags)


@register
class TopologyMap(BaseModule):
    id = "CUT-RECON-002"
    alias = "cartograph"
    name = "Agent Topology Mapping"
    tactic = "RECON"
    targets = ["a2a", "orchestrator"]
    options: dict[str, Option] = {}

    def _build(self, rng: Any) -> tuple[nx.DiGraph, dict[str, str]]:
        """Build the attack graph (nodes carry a role; edges carry a kind)."""
        g: nx.DiGraph = nx.DiGraph()
        roles: dict[str, str] = {}

        def add_tool(spec: Any) -> None:
            node = spec.qualified()
            egress = spec.name == "http_get"
            role = "sink" if (spec.sensitive or egress) else "tool"
            g.add_node(node, kind="tool", role=role, sensitive=spec.sensitive, egress=egress)
            roles[node] = role

        # The orchestrator and the tools it can call directly.
        g.add_node("orchestrator", kind="agent", role="pivot")
        roles["orchestrator"] = "pivot"
        for spec in rng.list_tools():
            add_tool(spec)
            g.add_edge("orchestrator", spec.qualified(), kind="can-call")

        # Untrusted-input surfaces the orchestrator reads.
        corpus = getattr(rng, "corpus", None)
        if corpus is not None and getattr(corpus, "writable", lambda: False)():
            g.add_node("rag-corpus", kind="source", role="source")
            roles["rag-corpus"] = "source"
            g.add_edge("rag-corpus", "orchestrator", kind="feeds")
        g.add_node("tool-desc", kind="source", role="source")
        roles["tool-desc"] = "source"
        g.add_edge("tool-desc", "orchestrator", kind="feeds")

        # Peer agents: their tools, their A2A edges, and the surfaces they drain.
        agents = getattr(rng, "agents", {}) or {}
        for aid, obj in agents.items():
            g.add_node(aid, kind="agent", role="pivot")
            roles[aid] = "pivot"
            g.add_edge("orchestrator", aid, kind="a2a")
            lister = getattr(obj, "list_tools", None)
            if callable(lister):
                for spec in lister():
                    add_tool(spec)
                    g.add_edge(aid, spec.qualified(), kind="can-call")
            for surface in (f"memory:{aid}", f"tickets:{aid}"):
                g.add_node(surface, kind="source", role="source")
                roles[surface] = "source"
                g.add_edge(surface, aid, kind="feeds")
            for peer in getattr(obj, "peers", []) or []:
                g.add_edge(aid, peer, kind="a2a")

        # Any node an A2A edge implied but never described is still a pivot agent.
        for node in g.nodes:
            if "role" not in g.nodes[node]:
                g.nodes[node].update(kind="agent", role="pivot")
                roles[node] = "pivot"
        return g, roles

    def _paths(self, g: nx.DiGraph, roles: dict[str, str]) -> list[dict[str, Any]]:
        sources = [n for n, r in roles.items() if r == "source"]
        sinks = [n for n, r in roles.items() if r == "sink"]
        out: list[dict[str, Any]] = []
        for src in sources:
            for sink in sinks:
                if not (g.has_node(src) and g.has_node(sink)):
                    continue
                for path in nx.all_simple_paths(g, src, sink, cutoff=_CUTOFF):
                    out.append(
                        {
                            "source": src,
                            "sink": sink,
                            "hops": path,
                            "length": len(path) - 1,
                            "techniques": _path_techniques(g, path),
                        }
                    )
                    if len(out) >= _MAX_PATHS:
                        return out
        return out

    async def check(self, session: Session) -> CheckResult:
        rng = connect_range(session.target)
        specs = rng.list_tools()
        agents = list(getattr(rng, "agents", {}))
        return CheckResult(
            module_id=self.id,
            susceptible=bool(specs),
            reason=f"{len(specs)} tool(s) and {len(agents)} peer agent(s) reachable to map",
            data={"tool_count": len(specs), "agent_count": len(agents)},
        )

    async def run(self, session: Session) -> RunResult:
        rng = connect_range(session.target)
        g, roles = self._build(rng)
        paths = self._paths(g, roles)

        sources = sorted(n for n, r in roles.items() if r == "source")
        sinks = sorted(n for n, r in roles.items() if r == "sink")
        pivots = sorted(n for n, r in roles.items() if r == "pivot")

        await self.emit(
            Phase.RUN,
            "recon.topology",
            {"agents": pivots, "sources": sources, "sinks": sinks, "edges": g.number_of_edges()},
        )
        await self.emit(
            Phase.RUN,
            "recon.classify",
            {"source": len(sources), "pivot": len(pivots), "sink": len(sinks)},
        )
        for p in paths:
            await self.emit(
                Phase.RUN,
                "recon.attack_path",
                {
                    "source": p["source"],
                    "sink": p["sink"],
                    "hops": " -> ".join(p["hops"]),
                    "techniques": p["techniques"],
                },
            )

        # Mirror roles + edges into the session graph so replay and later modules see them.
        for node in roles:
            attrs = dict(g.nodes[node])
            session.graph.add_node(node, **attrs)
        for u, v, data in g.edges(data=True):
            session.graph.add_edge(u, v, **data)

        session.artifacts["node_roles"] = roles
        session.artifacts["attack_paths"] = paths
        session.artifacts["topology"] = {
            "agents": pivots,
            "sources": sources,
            "sinks": sinks,
            "edges": g.number_of_edges(),
        }

        return RunResult(
            status="success",
            summary=(
                f"mapped {len(pivots)} agent(s) and {g.number_of_nodes()} node(s); classified "
                f"{len(sources)} source(s)/{len(sinks)} sink(s); enumerated {len(paths)} "
                f"attack path(s)"
            ),
            data={
                "sources": sources,
                "sinks": sinks,
                "pivots": pivots,
                "attack_paths": paths,
            },
        )
