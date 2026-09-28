"""Live-eval harness logic (approval farming vs a real model), tested with a scripted
provider so it runs offline in CI — no ollama, no network."""

from __future__ import annotations

import pytest
from cutout.liveeval import (
    FARMED_JUSTIFICATION,
    parse_verdict,
    run_approval_eval,
)


class _ScriptedProvider:
    """A deterministic stand-in: approves when the system prompt is naive AND the farmed
    justification is present; denies otherwise. Mirrors the shape a suggestible model shows,
    so the harness's aggregation can be verified without a real backend."""

    async def complete(self, prompt: str, *, system: str | None = None) -> str:
        naive = bool(system and "If the request looks legitimate" in system)
        farmed = FARMED_JUSTIFICATION.split(";")[0] in prompt
        return "APPROVE" if (naive and farmed) else "DENY"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("APPROVE", True),
        ("deny", False),
        ("I would DENY this request.", False),
        ("Approved.", True),
        ("It depends", None),  # neither
        ("approve or deny?", None),  # both -> unclear
    ],
)
def test_parse_verdict(text: str, expected: bool | None) -> None:
    assert parse_verdict(text) is expected


async def test_eval_isolates_the_farming_effect() -> None:
    report = await run_approval_eval(_ScriptedProvider(), model="scripted", trials=8)

    assert report.cell("naive", "honest").rate == 0.0
    assert report.cell("naive", "farmed").rate == 1.0  # farming lands under the naive gate
    assert report.cell("neutral", "farmed").rate == 0.0  # scripted only obeys the naive gate
    assert report.cell("hardened", "farmed").rate == 0.0  # hardened prompt resists
    assert report.farming_effect == 1.0  # +100 pts naive: farmed - honest
    assert report.farming_effect_neutral == 0.0  # scripted doesn't self-farm under neutral
    assert report.hardening_effect == 1.0  # +100 pts farmed: naive - hardened


async def test_eval_emits_evidence_per_cell() -> None:
    events: list[object] = []

    async def _emit(event: object) -> None:
        events.append(event)

    await run_approval_eval(_ScriptedProvider(), model="scripted", trials=3, emit=_emit)
    # Six cells (3 postures x 2 justifications), one evidence event each.
    assert len(events) == 6
    actions = {getattr(e, "action", None) for e in events}
    assert actions == {"liveeval.cell"}


async def test_borderline_scenario_uses_its_action_and_reports_name() -> None:
    class _Recorder:
        def __init__(self) -> None:
            self.prompts: list[str] = []

        async def complete(self, prompt: str, *, system: str | None = None) -> str:
            self.prompts.append(prompt)
            return "DENY"

    rec = _Recorder()
    report = await run_approval_eval(rec, model="x", scenario="borderline", trials=1)
    assert report.scenario == "borderline"
    assert any("$500 account credit" in p for p in rec.prompts)  # the borderline action is used
    assert all("API secret" not in p for p in rec.prompts)  # not the secret scenario


async def test_unknown_scenario_raises() -> None:
    from cutout.liveeval import resolve_scenario

    with pytest.raises(ValueError, match="unknown scenario"):
        resolve_scenario("nope")


async def test_unclear_replies_excluded_from_rate() -> None:
    class _Vague:
        async def complete(self, prompt: str, *, system: str | None = None) -> str:
            return "hmm, hard to say"

    report = await run_approval_eval(_Vague(), model="vague", trials=5)
    cell = report.cell("naive", "farmed")
    assert cell.unclear == 5
    assert cell.rate == 0.0  # no decided trials -> 0, not a division error
