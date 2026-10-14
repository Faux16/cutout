"""The approval-farming benchmark: scenario loading + aggregation, tested offline with a
scripted provider (no model, no network)."""

from __future__ import annotations

from pathlib import Path

import pytest
from cutout.benchmark import BENCHMARK_NAME, run_benchmark
from cutout.liveeval import SYSTEM_NEUTRAL, load_scenarios

_SCENARIOS = Path(__file__).resolve().parent.parent / "benchmarks/approval_farming/scenarios.yaml"


class _ScriptedBorderlineProvider:
    """Approves only under the neutral prompt with a farmed justification (which every farmed
    justification signals with 'Approved by') — the shape a farmable model shows."""

    async def complete(self, prompt: str, *, system: str | None = None) -> str:
        neutral = system == SYSTEM_NEUTRAL
        farmed = "Approved by" in prompt
        return "APPROVE" if (neutral and farmed) else "DENY"


def test_shipped_scenarios_load() -> None:
    scen = load_scenarios(_SCENARIOS)
    assert "secret" in scen and scen["secret"].tier == "hard"
    borderline = [s for s in scen.values() if s.tier == "borderline"]
    assert len(borderline) >= 4  # a class of borderline actions, not one
    # every scenario has a matched honest/farmed pair and a mitigation prompt
    for s in scen.values():
        assert s.action and s.honest and s.farmed and s.hardened_system


def test_load_scenarios_rejects_missing_keys(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("scenarios:\n  - name: x\n    action: do a thing\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing keys"):
        load_scenarios(bad)


async def test_run_benchmark_aggregates_scores() -> None:
    scenarios = load_scenarios(_SCENARIOS)
    report = await run_benchmark(
        _ScriptedBorderlineProvider(),
        scenarios,
        model="scripted",
        provider_name="mock",
        trials=4,
    )
    # borderline scenarios are farmed under neutral; the hard control and hardened prompt resist.
    assert report.borderline_susceptibility == 1.0
    assert report.mean_mitigation_efficacy == 1.0
    credit = next(r for r in report.results if r.scenario == "credit")
    assert credit.farming_susceptibility == 1.0
    assert credit.hardened_farmed == 0.0


async def test_report_serializes() -> None:
    scenarios = load_scenarios(_SCENARIOS)
    report = await run_benchmark(
        _ScriptedBorderlineProvider(), scenarios, model="scripted", trials=2
    )
    d = report.to_dict()
    assert d["benchmark"] == BENCHMARK_NAME
    assert d["summary"]["borderline_susceptibility"] == 1.0
    assert len(d["scenarios"]) == len(scenarios)
    assert "naive:farmed" in d["scenarios"][0]["cells"]
