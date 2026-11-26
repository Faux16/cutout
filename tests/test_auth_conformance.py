"""MCP auth-conformance benchmark — the audience (standin) and issuer (shellgame) probes,
the default-secure metrics, and the shipped corpus. Fully offline and deterministic."""

from __future__ import annotations

from pathlib import Path

import pytest
from cutout.auth_conformance import (
    Fixture,
    _audience_probe,
    _issuer_probe,
    load_corpus,
    run_auth_conformance,
)

_CORPUS = Path(__file__).resolve().parent.parent / "benchmarks/mcp_auth_conformance/corpus.yaml"


def test_audience_probe_discriminates() -> None:
    enforced = _audience_probe("enforced")
    assert enforced.testable and enforced.granted_by_default is False
    assert enforced.default_secure is True
    assert enforced.control_denied is True

    for insecure in ("opt-in", "none"):
        d = _audience_probe(insecure)
        assert d.testable and d.granted_by_default is True  # cross-audience token accepted
        assert d.default_secure is False
        assert d.control_denied is True  # the hardened control still rejects it -> probe is valid

    for na in ("na", "unknown"):
        d = _audience_probe(na)
        assert d.testable is False and d.default_secure is None


def test_issuer_probe_discriminates() -> None:
    enforced = _issuer_probe("enforced")
    assert enforced.default_secure is True and enforced.control_denied is True
    exposed = _issuer_probe("opt-in")
    assert exposed.granted_by_default is True and exposed.default_secure is False
    assert exposed.control_denied is True
    assert _issuer_probe("na").testable is False


async def _fixtures() -> list[Fixture]:
    return [
        Fixture("sec", "hand-rolled-jwt", audience="enforced", issuer="enforced", source="x"),
        Fixture("exp", "sdk-default", audience="opt-in", issuer="unknown", source="x"),
        Fixture("sym", "symmetric-secret", audience="na", issuer="na", source="x"),
    ]


async def test_metrics_over_small_corpus() -> None:
    report = await run_auth_conformance(await _fixtures())
    # audience-testable = {sec: enforced, exp: opt-in} -> 1 of 2 secure.
    assert report._testable_count("audience") == 2
    assert report.audience_default_secure_rate == 0.5
    # issuer-testable = {sec: enforced} only (unknown/na excluded) -> 100%.
    assert report._testable_count("issuer") == 1
    assert report.issuer_default_secure_rate == 1.0
    assert report.instrument_valid is True


async def test_emits_two_cells_per_fixture() -> None:
    events: list[object] = []

    async def _emit(e: object) -> None:
        events.append(e)

    fixtures = await _fixtures()
    await run_auth_conformance(fixtures, emit=_emit)
    assert len(events) == 2 * len(fixtures)
    assert {getattr(e, "action", None) for e in events} == {"authconf.cell"}


def test_load_corpus_validates_modes() -> None:
    with pytest.raises(ValueError, match="mode"):
        load_corpus_from_text(
            "fixtures:\n  - {name: a, kind: k, audience: bogus, issuer: na, source: s}\n"
        )
    with pytest.raises(ValueError, match="missing keys"):
        load_corpus_from_text("fixtures:\n  - {name: a, kind: k, audience: na}\n")


def load_corpus_from_text(text: str, tmp: Path | None = None) -> list[Fixture]:
    import tempfile

    p = Path(tempfile.mkstemp(suffix=".yaml")[1])
    p.write_text(text, encoding="utf-8")
    try:
        return load_corpus(p)
    finally:
        p.unlink(missing_ok=True)


async def test_shipped_corpus_is_consistent() -> None:
    fixtures = load_corpus(_CORPUS)
    assert len(fixtures) >= 15  # the survey target
    report = await run_auth_conformance(fixtures)
    assert report.instrument_valid is True
    # 6 enforced / 11 audience-testable in the shipped survey.
    assert report._testable_count("audience") == 11
    assert round(report.audience_default_secure_rate, 2) == 0.55
    # Every exposed fixture is opt-in (the thesis: insecure defaults, not missing checks).
    exposed = [r for r in report.results if r.audience.testable and not r.audience.default_secure]
    assert exposed and all(r.audience.mode == "opt-in" for r in exposed)
