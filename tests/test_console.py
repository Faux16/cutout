"""The interactive console drives the engine with persistent session state.

These are sync tests on purpose: the console calls ``asyncio.run`` internally, which
cannot run inside an already-running event loop.
"""

from __future__ import annotations

from pathlib import Path

from cutout.console import CutoutConsole
from cutout_range import reset_ranges


def _console(tmp_path: Path) -> CutoutConsole:
    reset_ranges()
    return CutoutConsole(session_transcript=tmp_path / "console.jsonl")


def test_use_sets_current_and_prompt(tmp_path: Path) -> None:
    con = _console(tmp_path)
    con.onecmd("use CUT-RECON-001")
    assert con.current == "CUT-RECON-001"
    assert "CUT-RECON-001" in con.prompt
    con.onecmd("back")
    assert con.current is None


def test_unknown_module_is_rejected(tmp_path: Path) -> None:
    con = _console(tmp_path)
    con.onecmd("use CUT-NOPE-999")
    assert con.current is None


def test_chain_accumulates_state_across_commands(tmp_path: Path) -> None:
    con = _console(tmp_path)
    # A whole attack chain in one persistent session, like msfconsole.
    con.onecmd("use CUT-RECON-001")
    con.onecmd("run")
    con.onecmd("use CUT-INJ-002")
    con.onecmd("run")
    con.onecmd("use CUT-EXEC-001")
    con.onecmd("run")

    # State persisted across the three runs against the same in-process range.
    assert [r.module_id for r in con.session.results] == [
        "CUT-RECON-001",
        "CUT-INJ-002",
        "CUT-EXEC-001",
    ]
    assert any("cutrange_FAKE_secret_VIP001" in v for v in con.session.secrets.values())
    assert con.transcript.events  # evidence recorded live
    con.onecmd("exit")


def test_scan_populates_hosts_and_services(tmp_path: Path) -> None:
    con = _console(tmp_path)
    con.onecmd("scan")
    assert con.session.artifacts.get("tools")  # services discovered
    assert "billing-agent" in con.session.artifacts.get("agents", [])  # peer host found
    assert con.session.graph.has_node("customer-data")
    # hosts/services render without error
    con.onecmd("hosts")
    con.onecmd("services")


def test_set_option_and_target(tmp_path: Path) -> None:
    con = _console(tmp_path)
    con.onecmd("use CUT-INJ-002")
    con.onecmd("set anchor shipping")
    assert con.opts["anchor"] == "shipping"
    con.onecmd("set TARGET http://127.0.0.1:8600")
    assert con.session.target.uri == "http://127.0.0.1:8600"
    con.onecmd("unset TARGET")
    assert con.session.target.uri is None
