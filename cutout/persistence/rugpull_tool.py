"""CUT-PERS-006 — Rug-Pull Tool.

A durable foothold that survives on *misplaced trust* rather than planted content: an
attacker-controlled tool is approved while it behaves benignly, then flips to malicious
behavior once it is trusted — the same call, under the same unchanged (benign, non-sensitive)
description, now exfiltrates a secret. This module proves the rug pull: it baselines the
tool's benign output pre-trust, arms it (the post-approval flip), and confirms the identical
call diverges — leaking a secret its advertised schema never hinted at.
"""

from __future__ import annotations

import inspect
from typing import Any

from cutout_range import connect_range

from cutout.engine.evidence import Phase
from cutout.engine.module import BaseModule, Option
from cutout.engine.registry import register
from cutout.engine.session import CheckResult, RunResult, Session


def _secret_in(data: Any) -> str | None:
    return str(data["api_secret"]) if isinstance(data, dict) and "api_secret" in data else None


async def _call(rng: Any, name: str, args: dict[str, Any]) -> dict[str, Any]:
    """Invoke a tool through whichever call_tool the target provides (sync or async)."""
    res = rng.call_tool(name, args)
    if inspect.isawaitable(res):
        res = await res
    return res  # type: ignore[no-any-return]


@register
class RugPullTool(BaseModule):
    id = "CUT-PERS-006"
    alias = "turncoat"
    name = "Rug-Pull Tool"
    tactic = "PERS"
    targets = ["mcp"]
    options = {
        "tool": Option(
            help="The approved, benign-looking tool that will rug-pull.",
            default="summarize_notes",
            type="str",
        ),
        "text": Option(
            help="Innocuous argument used for both the pre- and post-trust calls.",
            default="Customer asked about their refund status.",
            type="str",
        ),
    }

    async def check(self, session: Session) -> CheckResult:
        # Read-only: is the tool present and advertised as benign (non-sensitive) — i.e. the
        # kind of tool a human or policy would approve without a second look?
        rng = connect_range(session.target)
        spec = next((s for s in rng.list_tools() if s.name == self.opts["tool"]), None)
        approvable = spec is not None and not spec.sensitive
        return CheckResult(
            module_id=self.id,
            susceptible=approvable,
            reason=(
                f"tool '{self.opts['tool']}' advertises benign, non-sensitive behavior "
                "(approvable, yet its runtime behavior is attacker-controlled)"
                if approvable
                else f"tool '{self.opts['tool']}' not present or already flagged sensitive"
            ),
            data={"advertised": spec.model_dump() if spec else None},
        )

    async def run(self, session: Session) -> RunResult:
        rng = connect_range(session.target)
        tool = self.opts["tool"]
        args = {"text": self.opts["text"]}
        advertised = next((s for s in rng.list_tools() if s.name == tool), None)

        # 1) Approval-time behavior: benign, no secret. This is what earns the tool trust.
        before = await _call(rng, tool, args)
        benign = _secret_in(before.get("data")) is None
        await self.emit(
            Phase.RUN,
            "persist.baseline",
            {"tool": tool, "benign": benign, "data": before.get("data")},
        )

        # 2) The rug pull: the attacker flips the trusted tool post-approval. Its advertised
        #    schema does not change — only its behavior.
        rng.arm_rugpull()
        await self.emit(Phase.RUN, "persist.rugpull", {"tool": tool, "armed": rng.rugpull_armed()})

        # 3) Post-trust behavior: the identical call now leaks a secret.
        after = await _call(rng, tool, args)
        secret = _secret_in(after.get("data"))
        schema_unchanged = advertised is not None and advertised == next(
            (s for s in rng.list_tools() if s.name == tool), None
        )
        verified = benign and secret is not None and schema_unchanged

        if secret is not None:
            key = f"{tool}:{after['data'].get('id', '?')}"
            session.secrets[key] = secret
        session.artifacts["persistence_verified"] = verified
        session.artifacts["rugpull_schema_unchanged"] = schema_unchanged
        await self.emit(
            Phase.RUN,
            "persist.verify",
            {
                "tool": tool,
                "benign_before": benign,
                "leaked_after": secret is not None,
                "schema_unchanged": schema_unchanged,
            },
        )

        return RunResult(
            status="success" if verified else "failed",
            summary=(
                f"'{tool}' rug-pulled: benign at approval, leaked a secret once trusted "
                "(advertised schema unchanged)"
                if verified
                else f"'{tool}' did not rug-pull"
            ),
            data={
                "tool": tool,
                "benign_before": benign,
                "leaked_after": secret is not None,
                "schema_unchanged": schema_unchanged,
                "harvested_secret_key": f"{tool}:VIP-001" if secret else None,
            },
        )
