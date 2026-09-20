"""The one-shot CLI resolves modules by alias / substring, like the console."""

from __future__ import annotations

from pathlib import Path

import pytest
import typer
from cutout.cli import _hunt, _render_hops, _resolve, app
from cutout_range import reset_ranges
from typer.testing import CliRunner


def test_resolve_exact_id() -> None:
    assert _resolve("CUT-EXEC-001") == "CUT-EXEC-001"


def test_resolve_alias() -> None:
    assert _resolve("puppet") == "CUT-EXEC-001"
    assert _resolve("brushpass") == "CUT-LAT-002"


def test_resolve_unique_substring() -> None:
    assert _resolve("document") == "CUT-INJ-002"


def test_resolve_ambiguous_raises() -> None:
    with pytest.raises(typer.BadParameter):
        _resolve("lat")  # matches both LAT modules


def test_resolve_unknown_raises() -> None:
    with pytest.raises(typer.BadParameter):
        _resolve("nope")


async def test_hunt_recons_then_frisks_and_finds(tmp_path: Path) -> None:
    # `cutout hunt` chains casing + frisk; against the in-process range it should enumerate
    # tools and confirm reachable-resource findings.
    reset_ranges()
    session = await _hunt(str(tmp_path / "range"), tmp_path / "hunt.jsonl")
    assert session.artifacts.get("tools")  # recon enumerated tools
    findings = session.artifacts.get("resource_findings", [])
    tools = {f["tool"] for f in findings}
    assert "fs-tools.read_file" in tools  # frisk confirmed a capability


def test_paths_command_maps_and_lists_attack_paths() -> None:
    reset_ranges()
    result = CliRunner().invoke(app, ["paths"])
    assert result.exit_code == 0
    assert "attack path" in result.stdout  # the panel summary
    assert "walkin" in result.stdout  # a technique tag is surfaced per path


def test_paths_command_filters_by_technique() -> None:
    reset_ranges()
    result = CliRunner().invoke(app, ["paths", "-t", "courier"])
    assert result.exit_code == 0
    assert "courier" in result.stdout
    assert "filtered" in result.stdout  # a filter narrowed the set


def test_render_hops_marks_source_and_sink() -> None:
    roles = {"src": "source", "mid": "pivot", "snk": "sink"}
    rendered = _render_hops(["src", "mid", "snk"], roles)
    assert "src" in rendered and "snk" in rendered and "→" in rendered
