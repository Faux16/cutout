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


def test_fmt_value_is_compact_and_markup_safe() -> None:
    # Long, multi-line values are collapsed + truncated, and Rich markup is escaped
    # so a value containing brackets can't corrupt the rendered line.
    out = CutoutConsole._fmt_value("a\nb   c [bold]x[/bold] " + "z" * 200, width=40)
    assert "\n" not in out and len(out) <= 40 + 10  # collapsed + truncated (+ escape overhead)
    assert out.endswith("…")
    assert CutoutConsole._fmt_value("[red]hi[/red]") == r"\[red]hi\[/red]"


def test_help_status_and_banner_render(tmp_path: Path) -> None:
    con = _console(tmp_path)
    # None of the new UX commands should raise.
    con.onecmd("help")
    con.onecmd("help scan")
    con.onecmd("status")
    con.onecmd("banner")
    con.onecmd("use puppet")
    con.onecmd("status")  # with a module selected
    assert con.current == "CUT-EXEC-001"


def test_use_sets_current_and_prompt(tmp_path: Path) -> None:
    con = _console(tmp_path)
    con.onecmd("use CUT-RECON-001")
    assert con.current == "CUT-RECON-001"
    assert "casing" in con.prompt  # prompt shows the friendly alias
    con.onecmd("back")
    assert con.current is None


def test_use_by_alias(tmp_path: Path) -> None:
    con = _console(tmp_path)
    con.onecmd("use puppet")
    assert con.current == "CUT-EXEC-001"
    con.onecmd("use sleeper")
    assert con.current == "CUT-PERS-001"


def test_use_by_index_and_substring(tmp_path: Path) -> None:
    con = _console(tmp_path)
    # Index selection requires a prior listing (msfconsole's `use 0`).
    con.onecmd("search puppet")
    assert con._listing == ["CUT-EXEC-001"]
    con.onecmd("use 0")
    assert con.current == "CUT-EXEC-001"
    # Name/id substring selection, no ID memorization needed.
    con.onecmd("use document")  # unique to deaddrop's name (Indirect Injection via RAG/Document)
    assert con.current == "CUT-INJ-002"
    con.onecmd("use lat")  # matches several LAT modules -> ambiguous, selection unchanged
    assert con.current == "CUT-INJ-002"


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
    # probe produced rich host records with addresses/transport
    hosts = con.session.artifacts.get("hosts")
    assert hosts and all("endpoint" in h and "transport" in h for h in hosts)
    assert any(h["id"] == "customer-data" and h["transport"] == "in-process" for h in hosts)
    # hosts/services render without error
    con.onecmd("hosts")
    con.onecmd("services")


def test_frisk_populates_findings(tmp_path: Path) -> None:
    con = _console(tmp_path)
    con.onecmd("frisk")
    findings = con.session.artifacts.get("resource_findings")
    assert findings  # confirmed at least one reachable resource on the range
    tools = {f["tool"] for f in findings}
    assert "fs-tools.read_file" in tools  # local file read
    assert "external-fetch.http_get" in tools  # SSRF
    # findings view renders without error
    con.onecmd("findings")


def test_unreachable_target_does_not_crash(tmp_path: Path) -> None:
    con = _console(tmp_path)
    con.onecmd("set TARGET http://127.0.0.1:1")  # nothing listening -> connection refused
    # A connection error must be caught, not propagate out of the REPL.
    con.onecmd("scan")
    # Console is still alive and usable afterward.
    con.onecmd("unset TARGET")
    con.onecmd("use puppet")
    assert con.current == "CUT-EXEC-001"


def test_set_option_and_target(tmp_path: Path) -> None:
    con = _console(tmp_path)
    con.onecmd("use CUT-INJ-002")
    con.onecmd("set anchor shipping")
    assert con.opts["anchor"] == "shipping"
    con.onecmd("set TARGET http://127.0.0.1:8600")
    assert con.session.target.uri == "http://127.0.0.1:8600"
    con.onecmd("unset TARGET")
    assert con.session.target.uri is None


def test_set_target_without_port_warns(tmp_path: Path) -> None:
    con = _console(tmp_path)
    con.console.record = True  # capture Rich output
    con.onecmd("set TARGET http://127.0.0.1")
    out = con.console.export_text()
    assert "no port" in out.lower()
    # It's still set (we warn, not block).
    assert con.session.target.uri == "http://127.0.0.1"
