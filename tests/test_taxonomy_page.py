"""The published taxonomy page stays in sync with taxonomy/matrix.yaml."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_taxonomy_page_is_up_to_date() -> None:
    # If matrix.yaml changed but docs/index.html wasn't regenerated, this fails in CI.
    result = subprocess.run(
        [sys.executable, "scripts/build_taxonomy.py", "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
