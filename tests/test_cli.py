"""The one-shot CLI resolves modules by alias / substring, like the console."""

from __future__ import annotations

import pytest
import typer
from cutout.cli import _resolve


def test_resolve_exact_id() -> None:
    assert _resolve("CUT-EXEC-001") == "CUT-EXEC-001"


def test_resolve_alias() -> None:
    assert _resolve("puppet") == "CUT-EXEC-001"
    assert _resolve("brushpass") == "CUT-LAT-002"


def test_resolve_unique_substring() -> None:
    assert _resolve("inject") == "CUT-INJ-002"


def test_resolve_ambiguous_raises() -> None:
    with pytest.raises(typer.BadParameter):
        _resolve("lat")  # matches both LAT modules


def test_resolve_unknown_raises() -> None:
    with pytest.raises(typer.BadParameter):
        _resolve("nope")
