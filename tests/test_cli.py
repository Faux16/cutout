"""The one-shot CLI resolves modules by alias / substring, like the console."""

from __future__ import annotations

from pathlib import Path

import pytest
import typer
from cutout.cli import _hunt, _resolve
from cutout_range import reset_ranges


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
