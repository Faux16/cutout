"""Batch OSS-hunt survey — the study harness (`cutout hunt --targets`)."""

from __future__ import annotations

import json
from pathlib import Path

import cutout.cli as cli
from cutout.cli import _finding_classes, _survey_record, app
from cutout.engine import Session, TargetDescriptor
from typer.testing import CliRunner

runner = CliRunner()


def test_finding_classes_folds_capabilities_and_severity() -> None:
    findings = [
        {"capability": "local file read (SQL file function)", "severity": "high"},
        {"capability": "server-side request forgery (outbound fetch)", "severity": "medium"},
        {"capability": "command / code execution", "severity": "critical"},
    ]
    file_read, ssrf, code_exec, highest = _finding_classes(findings)
    assert (file_read, ssrf, code_exec) == (True, True, True)
    assert highest == "critical"

    none = _finding_classes([])
    assert none == (False, False, False, "-")


def test_survey_record_from_session() -> None:
    session = Session(
        target=TargetDescriptor(uri="mcp+stdio:x"),
        artifacts={
            "tools": [{"sensitive": True}, {"sensitive": False}],
            "hosts": [{"endpoint": "stdio://x"}],
            "resource_findings": [
                {"capability": "local file read (path parameter)", "severity": "high"}
            ],
        },
    )
    rec = _survey_record("mcp+stdio:x", session, Path("runs/x.jsonl"))
    assert rec["reachable"] is True
    assert rec["tools"] == 2 and rec["sensitive"] == 1
    assert rec["file_read"] is True and rec["ssrf"] is False
    assert rec["highest_severity"] == "high"


def test_hunt_requires_exactly_one_of_target_or_targets(tmp_path: Path) -> None:
    # Neither.
    assert runner.invoke(app, ["hunt"]).exit_code == 1
    # Both.
    tf = tmp_path / "t.txt"
    tf.write_text("mcp+stdio:x\n")
    assert runner.invoke(app, ["hunt", "mcp+stdio:x", "--targets", str(tf)]).exit_code == 1


def test_batch_survey_aggregates_and_writes_report(tmp_path: Path, monkeypatch) -> None:
    async def fake_hunt(target: str, transcript: Path) -> Session:
        if "bad" in target:
            raise RuntimeError("server did not come up")
        return Session(
            target=TargetDescriptor(uri=target),
            artifacts={
                "tools": [{"sensitive": True}],
                "hosts": [{"endpoint": f"stdio://{target}"}],
                "resource_findings": [
                    {"capability": "local file read (SQL file function)", "severity": "high"}
                ],
            },
        )

    monkeypatch.setattr(cli, "_hunt", fake_hunt)
    targets = tmp_path / "targets.txt"
    targets.write_text("mcp+stdio:good\n# a comment\nmcp+stdio:bad\n")
    report = tmp_path / "survey.json"

    result = runner.invoke(app, ["hunt", "--targets", str(targets), "--report", str(report)])
    assert result.exit_code == 0

    data = json.loads(report.read_text())
    agg = data["aggregate"]
    assert agg["targets_tested"] == 2
    assert agg["reachable"] == 1 and agg["unreachable"] == 1
    assert agg["file_read"] == 1 and agg["ssrf"] == 0
    assert agg["high_or_critical"] == 1
    # The Markdown table is written alongside the JSON.
    assert (tmp_path / "survey.md").exists()
    md = (tmp_path / "survey.md").read_text()
    assert "| # | Target |" in md and "unreachable" in md


def test_batch_survey_missing_file() -> None:
    assert runner.invoke(app, ["hunt", "--targets", "/no/such/targets.txt"]).exit_code == 1
