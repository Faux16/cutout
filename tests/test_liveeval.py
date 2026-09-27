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
    assert report.cell("hardened", "farmed").rate == 0.0  # hardened prompt resists
    assert report.farming_effect == 1.0  # +100 pts naive: farmed - honest
    assert report.hardening_effect == 1.0  # +100 pts farmed: naive - hardened


async def test_eval_emits_evidence_per_cell() -> None:
    events: list[object] = []

    async def _emit(event: object) -> None:
        events.append(event)

    await run_approval_eval(_ScriptedProvider(), model="scripted", trials=3, emit=_emit)
    # Four cells (posture x justification), one evidence event each.
    assert len(events) == 4
    actions = {getattr(e, "action", None) for e in events}
    assert actions == {"liveeval.cell"}


async def test_unclear_replies_excluded_from_rate() -> None:
    class _Vague:
        async def complete(self, prompt: str, *, system: str | None = None) -> str:
            return "hmm, hard to say"

    report = await run_approval_eval(_Vague(), model="vague", trials=5)
    cell = report.cell("naive", "farmed")
    assert cell.unclear == 5
    assert cell.rate == 0.0  # no decided trials -> 0, not a division error
