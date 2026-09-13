"""CUT-INV-001 — Session Inventory (reference stub).

A trivial, no-op module whose only job is to exercise the plumbing end to end: the
loader finds it, options are validated, it emits evidence events through the engine, and
its result is recorded so ``replay`` can re-narrate the run. It performs no attack and
reaches nothing external — it just accounts for what the current session already holds.
"""

from __future__ import annotations

from cutout.engine.evidence import Phase
from cutout.engine.module import BaseModule, Option
from cutout.engine.provider import Provider
from cutout.engine.registry import register
from cutout.engine.session import CheckResult, RunResult, Session


@register
class SessionInventory(BaseModule):
    id = "CUT-INV-001"
    name = "Session Inventory"
    tactic = "inventory"
    targets = ["orchestrator"]
    options = {
        "label": Option(
            help="Free-text label recorded with the inventory snapshot.",
            required=False,
            default="baseline",
            type="str",
        ),
    }

    async def check(self, session: Session) -> CheckResult:
        # Read-only: report what is present without touching session state.
        return CheckResult(
            module_id=self.id,
            susceptible=True,
            reason="session inventory is always available",
            data={"target": session.target.name},
        )

    async def run(self, session: Session) -> RunResult:
        label = self.opts.get("label", "baseline")
        await self.emit(Phase.RUN, "inventory.start", {"label": label})

        snapshot = {
            "target": session.target.name,
            "target_kind": session.target.kind,
            "graph_nodes": session.graph.number_of_nodes(),
            "graph_edges": session.graph.number_of_edges(),
            "artifacts": len(session.artifacts),
            "secrets": len(session.secrets),
            "prior_results": len(session.results),
        }
        # Prove the provider wiring works without any network call.
        provider: Provider | None = self.provider
        if provider is not None:
            ack = await provider.complete(f"inventory:{label}")
            snapshot["provider_ack"] = ack

        await self.emit(Phase.RUN, "inventory.snapshot", snapshot)

        return RunResult(
            status="success",
            summary=f"inventoried session '{session.id}' ({label})",
            data=snapshot,
        )
