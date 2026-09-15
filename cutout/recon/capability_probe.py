"""CUT-DISC-004 — Resource / Filesystem Discovery.

*Frisk* a target's tools for the resources they can reach — local files and internal
network — and *safely confirm* each capability with benign probes. Given a recon'd MCP
target (a real server or the bundled range), classify candidate tools and probe:

* **Local file read** — SQL query tools exposing DuckDB/SQLite file functions
  (``read_text``/``read_blob``), and path-taking file tools. Probe a benign, non-existent
  path: a function that *executes* while another is *blocked* (or a "no such file" from a
  path tool) is a file-read candidate; a validation refusal is defended. No real file is
  read — the oracle only distinguishes "tried to open" from "refused".
* **SSRF** — outbound-fetch tools. Probe loopback (a closed high port) and TEST-NET-1
  (RFC 5737, reserved/unroutable): reaching either means no egress filtering — a
  server-side request forgery sink. Cloud metadata is deliberately *not* auto-probed.

This is the reusable form of a real finding: a read-only ``query`` tool that still
permitted DuckDB ``read_text()`` / ``read_blob()`` was an arbitrary local file read
(the project's own filesystem denylist omitted those two functions). ``frisk`` re-finds
that class automatically; the range's ``fs-tools.read_file`` and ``external-fetch.http_get``
are the offline analogues.
"""

from __future__ import annotations

import inspect
import secrets
from typing import Any

from cutout_range import connect_range

from cutout.engine.evidence import Phase
from cutout.engine.module import BaseModule, Option
from cutout.engine.registry import register
from cutout.engine.session import CheckResult, RunResult, Session

# Param names / description keywords that mark a tool as SQL-capable (may host DuckDB or
# SQLite file-reading functions) or path-capable (takes a filesystem path directly).
_SQL_PARAMS = {"sql", "query", "statement", "q"}
_SQL_WORDS = {"sql", "query", "duckdb", "sqlite", "database", "select"}
_PATH_PARAMS = {"path", "file", "filename", "filepath", "file_path", "src"}
_PATH_WORDS = {"read_file", "readfile", "file", "path", "filesystem", "read a file"}

# DuckDB file-reading table functions to try inside a SELECT. read_text/read_blob are the
# ones real denylists forget; read_csv is the "usually blocked" control.
_SQL_FILE_FUNCS = ("read_text", "read_blob", "read_csv")

# Params / keywords that mark a tool as an outbound-fetch tool (a possible SSRF sink).
_FETCH_PARAMS = {"url", "uri", "endpoint", "link", "href", "address"}
_FETCH_WORDS = {"fetch", "http", "https", "request", "curl", "download", "webhook"}

# Benign SSRF probe targets. Loopback on a random closed high port proves the tool will
# reach *internal* services; TEST-NET-1 (192.0.2.0/24, RFC 5737, reserved for docs and
# guaranteed unroutable) proves it will fetch an arbitrary external host. Reaching either
# means no egress filtering. We deliberately do NOT auto-probe cloud metadata
# (169.254.169.254): reaching loopback already confirms the capability, without risking
# exfiltration of real instance credentials from a target under test.
# NB: the probe path must not contain any _SSRF_BLOCKED_MARKERS substring (e.g. "ssrf") —
# tools echo the URL back, which would otherwise self-match and read as "defended".
_SSRF_PROBES = (
    ("loopback", "http://127.0.0.1:{port}/cutout-probe"),
    ("reserved", "http://192.0.2.1/cutout-probe"),
)
# The tool attempted an outbound request to our internal/reserved target (no filtering).
_SSRF_ATTEMPTED_MARKERS = (
    "connection refused",
    "connection error",
    "connection reset",
    "failed to connect",
    "could not connect",
    "no route to host",
    "timed out",
    "timeout",
    "max retries",
    "econnrefused",
    "name or service not known",
    "temporary failure in name resolution",
    "connectionerror",
)
# The tool refused the internal/reserved destination (egress filtering / SSRF guard).
_SSRF_BLOCKED_MARKERS = (
    "not allowed",
    "blocked",
    "forbidden",
    "not permitted",
    "denied",
    "disallowed",
    "invalid url",
    "invalid host",
    "private",
    "internal address",
    "link-local",
    "must be http",
    "ssrf",
    "refused to fetch",
    "not a public",
)

# The server *tried to open* our made-up path -> the file-access capability is reachable.
_REACHABLE_MARKERS = (
    "no such file",
    "no such file or directory",
    "not found",
    "does not exist",
    "cannot open",
    "unable to open",
    "failed to open",
    "no files found",
    "errno 2",
    "ioerror",
    "io error",
)
# The server refused before touching the disk -> the capability is defended.
_BLOCKED_MARKERS = (
    "not permitted",
    "not allowed",
    "blocked",
    "forbidden",
    "disabled",
    "filesystem functions",
    "validation failed",
    "not a valid",
    "invalid",
    "denied",
)


def _has_signal(spec: Any, params: set[str], words: set[str]) -> bool:
    keys = {k.lower() for k in (spec.params or {})}
    text = f"{spec.name} {spec.description}".lower()
    return bool(keys & params) or any(w in text for w in words)


def _sql_param(spec: Any) -> str | None:
    for key in spec.params or {}:
        if str(key).lower() in _SQL_PARAMS:
            return str(key)
    return None


def _path_param(spec: Any) -> str | None:
    for key in spec.params or {}:
        if str(key).lower() in _PATH_PARAMS:
            return str(key)
    return None


def _fetch_param(spec: Any) -> str | None:
    for key in spec.params or {}:
        if str(key).lower() in _FETCH_PARAMS:
            return str(key)
    return None


def _classify(text: str) -> str:
    """Read a tool's error/output string as reachable | defended | inconclusive."""
    low = text.lower()
    if any(m in low for m in _REACHABLE_MARKERS):
        return "reachable"
    if any(m in low for m in _BLOCKED_MARKERS):
        return "defended"
    return "inconclusive"


def _sql_verdict(res: dict[str, Any]) -> str:
    """Read a SQL file-function probe as reachable | defended | inconclusive.

    The probe path does not exist, so a file-reading function either (a) is *blocked*
    by validation, (b) *executes* — returning a query result (rows/fields) or a
    file-not-found error, proving it reached the filesystem layer — or (c) is merely
    *planned* (EXPLAIN returns a ``plan``, never touching the disk). Only (b) confirms.
    """
    low = _envelope_text(res).lower()
    if any(m in low for m in _BLOCKED_MARKERS):
        return "defended"
    if any(m in low for m in _REACHABLE_MARKERS):
        return "reachable"
    data = res.get("data")
    if res.get("ok") and isinstance(data, dict) and ("rows" in data or "fields" in data):
        return "reachable"  # the function executed as a query (not blocked, not just planned)
    return "inconclusive"


def _ssrf_verdict(res: dict[str, Any]) -> str:
    """Read an SSRF probe as reachable | defended | inconclusive.

    The target is internal (loopback) or reserved (TEST-NET), so a fetch tool with no
    egress filtering either returns a response (mocked ranges, or a live internal
    service) or *attempts* the connection and fails at the socket layer (connection
    refused / timeout) — both prove it tried. A tool with an SSRF guard refuses the
    destination outright.
    """
    low = _envelope_text(res).lower()
    if any(m in low for m in _SSRF_BLOCKED_MARKERS):
        return "defended"
    if res.get("ok"):
        return "reachable"  # returned a response for an internal/reserved target
    if any(m in low for m in _SSRF_ATTEMPTED_MARKERS):
        return "reachable"  # attempted the outbound request to an internal/reserved host
    return "inconclusive"


def _envelope_text(res: dict[str, Any]) -> str:
    """Flatten a call envelope to the text we pattern-match on."""
    return f"{res.get('error', '')} {res.get('text', '')} {res.get('data', '')}"


@register
class FilesystemDiscovery(BaseModule):
    id = "CUT-DISC-004"
    alias = "frisk"
    name = "Resource / Filesystem Discovery"
    tactic = "DISC"
    targets = ["tool", "mcp"]
    options: dict[str, Option] = {
        "probe_path": Option(
            help="Benign non-existent path to probe with (default: a random one).",
            required=False,
            default="",
        ),
    }

    def _candidates(self, specs: list[Any]) -> list[tuple[Any, str | None, str | None, str | None]]:
        """Tools with a resource-reach signal, tagged with their sql/path/fetch param."""
        out: list[tuple[Any, str | None, str | None, str | None]] = []
        for spec in specs:
            sql = _sql_param(spec) if _has_signal(spec, _SQL_PARAMS, _SQL_WORDS) else None
            path = _path_param(spec) if _has_signal(spec, _PATH_PARAMS, _PATH_WORDS) else None
            fetch = _fetch_param(spec) if _has_signal(spec, _FETCH_PARAMS, _FETCH_WORDS) else None
            if sql or path or fetch:
                out.append((spec, sql, path, fetch))
        return out

    async def check(self, session: Session) -> CheckResult:
        rng = connect_range(session.target)
        specs = rng.list_tools()
        candidates = self._candidates(specs)
        names = [s.qualified() for s, *_ in candidates]
        return CheckResult(
            module_id=self.id,
            susceptible=bool(candidates),
            reason=(
                f"{len(candidates)} tool(s) with resource-reach potential: {', '.join(names)}"
                if candidates
                else "no tools expose a query/path/url parameter"
            ),
            data={"candidates": names},
        )

    async def _call(self, rng: Any, name: str, args: dict[str, Any]) -> dict[str, Any]:
        """Invoke a tool through whichever call_tool the target provides (sync or async)."""
        res = rng.call_tool(name, args)
        if inspect.isawaitable(res):
            res = await res
        return res  # type: ignore[no-any-return]

    async def run(self, session: Session) -> RunResult:
        rng = connect_range(session.target)
        probe_path = self.opts.get("probe_path") or (
            f"/nonexistent/cutout-probe-{secrets.token_hex(6)}"
        )
        await self.emit(Phase.RUN, "frisk.begin", {"probe_path": probe_path})

        specs = rng.list_tools()
        candidates = self._candidates(specs)
        findings: list[dict[str, Any]] = []

        for spec, sql_key, path_key, fetch_key in candidates:
            qualified = spec.qualified()

            # 1) SQL file-read: try DuckDB read_text/read_blob (missed by real denylists)
            #    and read_csv (the "usually blocked" control) against a made-up path. Probe
            #    all three so the finding can show the *gap* — functions that execute while
            #    others are blocked is exactly the incomplete-denylist bug.
            if sql_key:
                reachable_funcs: list[str] = []
                blocked_funcs: list[str] = []
                for func in _SQL_FILE_FUNCS:
                    payload = f"SELECT content FROM {func}('{probe_path}')"
                    res = await self._call(rng, spec.name, {sql_key: payload})
                    verdict = _sql_verdict(res)
                    await self.emit(
                        Phase.RUN,
                        "frisk.probe",
                        {"tool": qualified, "vector": f"sql:{func}", "verdict": verdict},
                    )
                    if verdict == "reachable":
                        reachable_funcs.append(func)
                    elif verdict == "defended":
                        blocked_funcs.append(func)
                if reachable_funcs:
                    gap = f" while {', '.join(blocked_funcs)} was blocked" if blocked_funcs else ""
                    findings.append(
                        {
                            "tool": qualified,
                            "capability": "local file read (SQL file function)",
                            "vector": f"{sql_key}=SELECT ... FROM {reachable_funcs[0]}('<path>')",
                            "reachable_functions": reachable_funcs,
                            "blocked_functions": blocked_funcs,
                            "severity": "high",
                            "detail": (
                                f"{', '.join(reachable_funcs)} executed through the query "
                                f"tool{gap} — arbitrary local file read candidate "
                                "(filesystem-denylist gap)."
                            ),
                        }
                    )

            # 2) Path file-read: hand the tool a made-up path directly.
            if path_key and not any(f["tool"] == qualified for f in findings):
                res = await self._call(rng, spec.name, {path_key: probe_path})
                verdict = _classify(_envelope_text(res))
                await self.emit(
                    Phase.RUN,
                    "frisk.probe",
                    {"tool": qualified, "vector": f"path:{path_key}", "verdict": verdict},
                )
                if verdict == "reachable":
                    findings.append(
                        {
                            "tool": qualified,
                            "capability": "local file read (path parameter)",
                            "vector": f"{path_key}=<path>",
                            "severity": "high",
                            "detail": (
                                "the tool opened an attacker-supplied path — path "
                                "traversal / arbitrary file read candidate."
                            ),
                        }
                    )

            # 3) SSRF: will an outbound-fetch tool reach internal / arbitrary hosts?
            #    Probe loopback (internal services) and TEST-NET (arbitrary external) —
            #    both benign. No filtering on either is a server-side request forgery sink.
            if fetch_key and not any(f["tool"] == qualified for f in findings):
                reached: list[str] = []
                for label, tmpl in _SSRF_PROBES:
                    url = tmpl.format(port=secrets.randbelow(20000) + 40000)
                    res = await self._call(rng, spec.name, {fetch_key: url})
                    verdict = _ssrf_verdict(res)
                    await self.emit(
                        Phase.RUN,
                        "frisk.probe",
                        {"tool": qualified, "vector": f"ssrf:{label}", "verdict": verdict},
                    )
                    if verdict == "reachable":
                        reached.append(label)
                if reached:
                    loopback = "loopback" in reached
                    findings.append(
                        {
                            "tool": qualified,
                            "capability": "server-side request forgery (outbound fetch)",
                            "vector": f"{fetch_key}=http://<internal-or-reserved-host>/",
                            "reached": reached,
                            "severity": "high" if loopback else "medium",
                            "detail": (
                                f"the fetch tool reached {', '.join(reached)} target(s) with "
                                "no egress filtering — SSRF candidate"
                                + (
                                    " (internal services / cloud metadata reachable)."
                                    if loopback
                                    else " (arbitrary external fetch; internal filtering "
                                    "unconfirmed)."
                                )
                            ),
                        }
                    )

        for f in findings:
            session.graph.add_node(f["tool"], kind="tool", resource_reach=True)
        session.artifacts["resource_findings"] = findings

        await self.emit(
            Phase.RUN,
            "frisk.result",
            {"candidates": len(candidates), "confirmed": len(findings)},
        )
        status = "success" if candidates else "skipped"
        if findings:
            hot = ", ".join(f"{f['tool']} ({f['capability'].split(' (')[0]})" for f in findings)
            summary = (
                f"resource reach CONFIRMED on {len(findings)}/{len(candidates)} "
                f"candidate tool(s): {hot}"
            )
        else:
            summary = f"probed {len(candidates)} candidate tool(s); no resource reach confirmed"
        return RunResult(status=status, summary=summary, data={"findings": findings})
