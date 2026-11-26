"""CUT-DISC-004 — frisk tools for filesystem reach and confirm it safely."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from uuid import uuid4

import pytest
from cutout.engine import Engine, Session, TargetDescriptor
from cutout.recon.capability_probe import (
    FilesystemDiscovery,
    _classify,
    _discover_allowed_root,
    _exec_verdict,
    _is_array_path,
    _is_containment_denial,
    _path_arg,
    _plant_canary,
    _sql_verdict,
    _ssrf_verdict,
)
from cutout_range import connect_range, reset_ranges


@pytest.fixture(autouse=True)
def _isolate() -> None:
    reset_ranges()


def _session() -> Session:
    return Session(
        target=TargetDescriptor(
            kind="range", name="cutout-range", metadata={"range_id": f"test-{uuid4().hex[:8]}"}
        )
    )


def test_classify_reads_error_strings() -> None:
    assert _classify("Error: No such file or directory") == "reachable"
    assert _classify("read_csv is not permitted via MCP") == "defended"
    assert _classify("[]") == "inconclusive"


def test_sql_verdict_distinguishes_execute_plan_and_block() -> None:
    # Executed as a query (rows/fields present) -> the file function ran -> reachable,
    # even when the made-up path matched no file (0 rows).
    assert _sql_verdict({"ok": True, "data": {"rows": [], "fields": [{"name": "content"}]}}) == (
        "reachable"
    )
    # Blocked by validation -> defended.
    assert (
        _sql_verdict({"ok": False, "error": "filesystem functions are not permitted via MCP"})
        == "defended"
    )
    # Merely PLANNED (EXPLAIN returns a plan, never touches the disk) -> NOT a confirmation.
    # This is the false-positive that must stay inconclusive.
    assert (
        _sql_verdict({"ok": True, "data": {"plan": "READ_TEXT", "estimated_rows": 1}})
        == "inconclusive"
    )
    # A non-SQL tool that echoes a list -> inconclusive.
    assert _sql_verdict({"ok": True, "data": []}) == "inconclusive"


async def test_frisk_check_flags_filesystem_candidates() -> None:
    session = _session()
    result = await FilesystemDiscovery().check(session)
    # The range's fs-tools.read_file (path param) is a candidate.
    assert result.susceptible is True
    assert "fs-tools.read_file" in result.data["candidates"]


def test_ssrf_verdict_distinguishes_reach_and_block() -> None:
    # Returned a response for an internal/reserved target -> reachable.
    assert _ssrf_verdict({"ok": True, "data": {"status": 200}}) == "reachable"
    # Attempted the connection and failed at the socket -> still reachable (it tried).
    assert _ssrf_verdict({"ok": False, "error": "Connection refused"}) == "reachable"
    # An SSRF guard refused the destination -> defended.
    assert _ssrf_verdict({"ok": False, "error": "requests to private addresses are blocked"}) == (
        "defended"
    )
    assert _ssrf_verdict({"ok": False, "error": "weird"}) == "inconclusive"


async def test_frisk_confirms_path_file_read_on_range() -> None:
    session = _session()
    engine = Engine(session=session)
    result = await engine.run("CUT-DISC-004")
    assert result.status == "success"

    findings = session.artifacts["resource_findings"]
    tools = {f["tool"] for f in findings}
    # read_file opened our made-up path -> confirmed reachable (file-read candidate).
    assert "fs-tools.read_file" in tools
    # search_customers has a `query` param (a signal) but is not a real SQL engine,
    # so the probe must NOT confirm it — signal candidates get cleared by the probe.
    assert "customer-data.search_customers" not in tools


async def test_frisk_confirms_ssrf_on_range() -> None:
    session = _session()
    engine = Engine(session=session)
    await engine.run("CUT-DISC-004")

    findings = session.artifacts["resource_findings"]
    ssrf = [f for f in findings if "request forgery" in f["capability"]]
    # external-fetch.http_get performs no URL validation -> SSRF confirmed.
    assert any(f["tool"] == "external-fetch.http_get" for f in ssrf)
    assert ssrf[0]["severity"] == "high"  # loopback reachable in the range mock


def test_exec_verdict_confirms_only_on_computed_result() -> None:
    # The product (marker) is not in the payload, so its presence proves execution.
    assert _exec_verdict({"ok": True, "data": "3895416"}, "3895416") == "reachable"
    # A per-payload failure (wrong language) is inconclusive — the other payload confirms.
    assert _exec_verdict({"ok": False, "error": "print: command not found"}, "3895416") == (
        "inconclusive"
    )
    # An explicit guard reads as defended.
    assert _exec_verdict({"ok": False, "error": "command execution is disabled"}, "3895416") == (
        "defended"
    )


async def test_frisk_confirms_command_exec_on_range() -> None:
    session = _session()
    engine = Engine(session=session)
    await engine.run("CUT-DISC-004")

    findings = session.artifacts["resource_findings"]
    ex = [f for f in findings if "execution" in f["capability"]]
    # code-exec.run_python evaluates the expression and returns the result -> confirmed.
    assert any(f["tool"] == "code-exec.run_python" for f in ex)
    assert ex[0]["severity"] == "critical"


def test_plant_canary_real_file_for_non_range_target(tmp_path: Path) -> None:
    # A target without a plant hook (a real server) gets a real temp-file canary.
    class _NoPlant:
        pass

    path, token, cleanup = _plant_canary(_NoPlant(), str(tmp_path))
    p = Path(path)
    assert p.exists() and token in p.read_text(encoding="utf-8")
    cleanup()
    assert not p.exists()  # cleaned up


def test_plant_canary_uses_range_virtual_fs() -> None:
    rng = connect_range(_session().target)
    path, token, cleanup = _plant_canary(rng, "")

    async def _check() -> None:
        res = await rng.call_tool("read_file", {"path": path})
        assert res["ok"] and token in str(res["data"])  # readable through the tool
        cleanup()
        gone = await rng.call_tool("read_file", {"path": path})
        assert gone["ok"] is False  # removed on cleanup

    asyncio.run(_check())


async def test_frisk_canary_confirms_file_read_definitively() -> None:
    session = _session()
    engine = Engine(session=session)
    await engine.run("CUT-DISC-004", {"canary": "true"})

    findings = session.artifacts["resource_findings"]
    read = [f for f in findings if f["tool"] == "fs-tools.read_file"]
    assert read, "canary read-back should confirm fs-tools.read_file"
    # Definitive: confirmed by the tool returning the planted canary's contents.
    assert read[0]["confirmed"] == "canary"
    assert "returned the planted canary" in read[0]["detail"]


async def test_frisk_skips_when_no_candidates() -> None:
    # A tool exposing no query/path parameter is not a candidate.
    mod = FilesystemDiscovery()

    class _Spec:
        server = "s"
        name = "ping"
        description = "healthcheck"
        params: dict[str, str] = {}

        def qualified(self) -> str:
            return "s.ping"

    assert mod._candidates([_Spec()]) == []


# --- prefix-collision probe (CVE-2025-53110 class) -------------------------------------


def test_discover_allowed_root_parses_denial_strings() -> None:
    assert (
        _discover_allowed_root(
            "Access denied - path outside allowed directories: /x not in /srv/jail"
        )
        == "/srv/jail"
    )
    assert _discover_allowed_root("Allowed directories: ['/home/me/work']") == "/home/me/work"
    assert _discover_allowed_root("must be within /data/share/") == "/data/share"
    # Nothing to parse / a bare root is ignored.
    assert _discover_allowed_root("some unrelated error") is None
    assert _discover_allowed_root("not in /") is None


def test_containment_and_array_helpers() -> None:
    assert _is_containment_denial("path outside allowed directories") is True
    assert _is_containment_denial("file read ok") is False
    assert _is_array_path("paths") is True
    assert _is_array_path("path") is False
    assert _path_arg("paths", "/f") == {"paths": ["/f"]}
    assert _path_arg("path", "/f") == {"path": "/f"}


def _array_path_spec() -> object:
    class _Spec:
        server = "stdio-server"
        name = "read_files"
        description = "Files to read. Each item is a plain path string."
        params = {"paths": "str", "limit": "str"}

        def qualified(self) -> str:
            return "stdio-server.read_files"

    return _Spec()


def test_candidates_detect_array_path_param() -> None:
    # read_files exposes `paths` (an array path param) — frisk must treat it as a path tool.
    cands = FilesystemDiscovery()._candidates([_array_path_spec()])
    assert len(cands) == 1
    _spec, _sql, path_key, _fetch, _cmd = cands[0]
    assert path_key == "paths"


class _FakeFsServer:
    """A filesystem server whose containment check is the buggy bare ``startswith`` (no path
    boundary) — the CVE-2025-53110 shape. Reads real files so the probe's planted canary is
    genuinely returned. ``secure=True`` adds the missing boundary."""

    def __init__(self, root: str, *, secure: bool = False) -> None:
        self.root = root
        self.secure = secure

    def _allowed(self, p: str) -> bool:
        if self.secure:
            return p == self.root or p.startswith(self.root + os.sep)
        return p.startswith(self.root)  # the bug

    def call_tool(self, name: str, args: dict[str, object]) -> dict[str, object]:
        raw = args.get("path")
        if raw is None and isinstance(args.get("paths"), list):
            raw = args["paths"][0]
        p = str(raw)
        if not self._allowed(p):
            msg = f"Access denied - path outside allowed directories: {p} not in {self.root}"
            return {"ok": True, "tool": name, "text": msg}
        try:
            with open(p, encoding="utf-8") as fh:
                return {"ok": True, "tool": name, "text": fh.read()}
        except OSError as exc:
            return {"ok": True, "tool": name, "text": f"no such file: {exc}"}


async def test_prefix_collision_probe_confirms_escape(tmp_path: Path) -> None:
    root = str(tmp_path / "jail")
    os.mkdir(root)
    server = _FakeFsServer(root)
    mod = FilesystemDiscovery()
    control = f"Access denied - path outside allowed directories: /etc/hostname not in {root}"
    finding = await mod._prefix_collision_probe(server, _array_path_spec(), "paths", control)

    assert finding is not None
    assert finding["capability"] == "path containment escape (prefix collision)"
    assert finding["confirmed"] == "canary"
    assert finding["allowed_root"] == root
    assert finding["severity"] == "high"
    # The probe cleaned up after itself: no sibling dir left behind.
    leftovers = [p for p in (tmp_path).iterdir() if p.name.startswith("jail-cutoutprobe-")]
    assert leftovers == []


async def test_prefix_collision_probe_defended_server_no_finding(tmp_path: Path) -> None:
    root = str(tmp_path / "jail")
    os.mkdir(root)
    server = _FakeFsServer(root, secure=True)  # proper boundary check
    mod = FilesystemDiscovery()
    control = f"Access denied - path outside allowed directories: /etc/hostname not in {root}"
    finding = await mod._prefix_collision_probe(server, _array_path_spec(), "paths", control)
    assert finding is None


async def test_prefix_collision_probe_skips_without_discoverable_root(tmp_path: Path) -> None:
    server = _FakeFsServer(str(tmp_path))
    mod = FilesystemDiscovery()
    # No allowed-root leaked in the control text -> nothing to aim at -> no finding, no writes.
    finding = await mod._prefix_collision_probe(server, _array_path_spec(), "paths", "opaque error")
    assert finding is None
