"""CUT-DISC-004 — frisk tools for filesystem reach and confirm it safely."""

from __future__ import annotations

from uuid import uuid4

import pytest
from cutout.engine import Engine, Session, TargetDescriptor
from cutout.recon.capability_probe import FilesystemDiscovery, _classify, _sql_verdict
from cutout_range import reset_ranges


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


async def test_frisk_confirms_path_file_read_on_range() -> None:
    session = _session()
    engine = Engine(session=session)
    result = await engine.run("CUT-DISC-004")
    assert result.status == "success"

    findings = session.artifacts["filesystem_findings"]
    tools = {f["tool"] for f in findings}
    # read_file opened our made-up path -> confirmed reachable (file-read candidate).
    assert "fs-tools.read_file" in tools
    # search_customers has a `query` param (a signal) but is not a real SQL engine,
    # so the probe must NOT confirm it — signal candidates get cleared by the probe.
    assert "customer-data.search_customers" not in tools
    assert all(f["severity"] == "high" for f in findings)


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
