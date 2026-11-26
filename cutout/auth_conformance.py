"""The MCP auth-conformance benchmark — a reproducible measurement of how a population of
real MCP-OAuth servers conforms to the 2026-07-28 token rules, and a runnable conformance
harness anyone can point at their own server.

The 2026-07-28 MCP spec requires a resource server to accept **only tokens issued for itself**
(RFC 8707 audience binding) and to validate the issuer (RFC 9207). The audience-confusion class
is public (the Tachyonic MCP-SDK audit; CVE-2026-111771 / GHSA-rvq5-wwqv-78pq). What was *not*
measured is **prevalence** — and, more sharply, whether servers are **secure by default** or
only when an operator explicitly flips a flag. A code survey of real MCP-OAuth servers found the
telling pattern: audience enforcement is frequently *opt-in* (``require_audience=False``,
``verify_aud=False`` unless configured, the SDK's own ``validate_resource=False``), so the
vulnerability is less "can't check ``aud``" than "ships with the check off".

This operationalizes that. Each surveyed server is encoded as a :class:`Fixture` carrying its
**as-shipped default** posture; the two instruments — ``standin`` (CUT-EXEC-005, audience
confusion) and ``shellgame`` (CUT-CRED-004, issuer mix-up) — probe it against the offline
:mod:`cutout_range.mcp_auth` model. The headline is the **default-secure rate**: the fraction of
servers (where the threat is applicable) that reject a cross-audience / wrong-issuer token *by
default*. A hardened control for every probe proves the instrument discriminates, and the whole
corpus runs offline in milliseconds (the kiosk constraint). Maps to OWASP ASI03.

Authorized use only — the optional live probe targets a server you own (see ETHICS.md).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from statistics import mean
from typing import Any

import yaml
from cutout_range.mcp_auth import DEFAULT_ISSUER, AuthServer, ResourceServer

from cutout.engine.evidence import EvidenceEvent, Phase

BENCHMARK_NAME = "mcp-auth-conformance"
BENCHMARK_VERSION = 1

#: Canonical identities the probes use. The server-under-test is issued tokens for THIS_AUD by
#: HONEST_ISS; the attacks present a token for OTHER_AUD (wrong audience) or from ATTACKER_ISS
#: (wrong issuer).
THIS_AUD = "https://mcp.example/this"
OTHER_AUD = "https://mcp.example/other"
HONEST_ISS = DEFAULT_ISSUER
ATTACKER_ISS = "https://auth.attacker.example"

#: A dimension's declared posture. ``enforced`` = checks by default; ``opt-in`` = can check but
#: ships with it off; ``none`` = no check available; ``na`` = the threat does not apply
#: (symmetric-secret / static-bearer servers — a cross-audience token cannot be forged without
#: the secret); ``unknown`` = not observed in the survey.
MODES = ("enforced", "opt-in", "none", "na", "unknown")
_AUD_TESTABLE = {"enforced", "opt-in", "none"}
_ISS_TESTABLE = {"enforced", "opt-in", "none"}
_REQUIRED_KEYS = ("name", "kind", "audience", "issuer", "source")

#: Evidence is attributed to the instrument that performs each probe.
_AUD_MODULE = "CUT-EXEC-005"  # standin — audience confusion (RFC 8707)
_ISS_MODULE = "CUT-CRED-004"  # shellgame — issuer mix-up (RFC 9207)


@dataclass(slots=True)
class Fixture:
    """One surveyed server's as-shipped auth posture, with a source citation."""

    name: str
    # kind: hand-rolled-jwt | sdk-delegated | sdk-default | library | symmetric-secret | static
    kind: str
    audience: str  # one of MODES
    issuer: str  # one of MODES
    source: str  # repo:path or advisory the classification is grounded in
    note: str = ""


@dataclass(slots=True)
class DimensionResult:
    """The outcome of probing one dimension (audience or issuer) of a fixture."""

    dimension: str
    mode: str
    testable: bool
    granted_by_default: bool | None  # did the attack token get in under the as-shipped default?
    control_denied: (
        bool | None
    )  # did the hardened control reject the same token? (proves the probe)

    @property
    def default_secure(self) -> bool | None:
        """Secure by default = the attack was rejected without any extra configuration."""
        if not self.testable:
            return None
        return not self.granted_by_default

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "testable": self.testable,
            "granted_by_default": self.granted_by_default,
            "default_secure": self.default_secure,
            "control_denied": self.control_denied,
        }


@dataclass(slots=True)
class FixtureResult:
    fixture: Fixture
    audience: DimensionResult
    issuer: DimensionResult

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.fixture.name,
            "kind": self.fixture.kind,
            "source": self.fixture.source,
            "note": self.fixture.note,
            "audience": self.audience.to_dict(),
            "issuer": self.issuer.to_dict(),
        }


def _audience_probe(mode: str) -> DimensionResult:
    """standin (RFC 8707): present a validly-signed token issued for *another* audience."""
    if mode not in _AUD_TESTABLE:
        return DimensionResult(
            "audience", mode, testable=False, granted_by_default=None, control_denied=None
        )
    validate = mode == "enforced"
    sut = ResourceServer(
        id="sut", audience=THIS_AUD, data={"secret": "x"}, validate_audience=validate
    )
    cross = AuthServer(issuer=HONEST_ISS).mint(OTHER_AUD)  # valid signature, wrong audience
    granted = bool(sut.access(cross).get("ok"))
    hardened = ResourceServer(id="sut", audience=THIS_AUD, validate_audience=True)
    control_denied = not bool(hardened.access(cross).get("ok"))
    return DimensionResult(
        "audience", mode, testable=True, granted_by_default=granted, control_denied=control_denied
    )


def _issuer_probe(mode: str) -> DimensionResult:
    """shellgame (RFC 9207): present a right-audience token minted by an *untrusted* issuer."""
    if mode not in _ISS_TESTABLE:
        return DimensionResult(
            "issuer", mode, testable=False, granted_by_default=None, control_denied=None
        )
    trusted = HONEST_ISS if mode == "enforced" else None
    sut = ResourceServer(id="sut", audience=THIS_AUD, trusted_issuer=trusted)
    foreign = AuthServer(issuer=ATTACKER_ISS).mint(THIS_AUD)  # right audience, wrong issuer
    granted = bool(sut.access(foreign).get("ok"))
    hardened = ResourceServer(id="sut", audience=THIS_AUD, trusted_issuer=HONEST_ISS)
    control_denied = not bool(hardened.access(foreign).get("ok"))
    return DimensionResult(
        "issuer", mode, testable=True, granted_by_default=granted, control_denied=control_denied
    )


@dataclass(slots=True)
class AuthConformanceReport:
    """The corpus run: every fixture's two-dimension result plus the headline rates."""

    results: list[FixtureResult] = field(default_factory=list)
    corpus: str = BENCHMARK_NAME
    version: int = BENCHMARK_VERSION

    def _dim(self, name: str, r: FixtureResult) -> DimensionResult:
        return r.audience if name == "audience" else r.issuer

    def _secure_rate(self, dimension: str) -> float:
        vals = [
            self._dim(dimension, r).default_secure
            for r in self.results
            if self._dim(dimension, r).testable
        ]
        return mean(1.0 if v else 0.0 for v in vals) if vals else 0.0

    def _testable_count(self, dimension: str) -> int:
        return sum(1 for r in self.results if self._dim(dimension, r).testable)

    def _distribution(self, dimension: str) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in self.results:
            m = self._dim(dimension, r).mode
            out[m] = out.get(m, 0) + 1
        return out

    @property
    def audience_default_secure_rate(self) -> float:
        """Fraction of audience-testable servers that reject a cross-audience token by default."""
        return self._secure_rate("audience")

    @property
    def issuer_default_secure_rate(self) -> float:
        """Fraction of issuer-testable servers that reject an untrusted issuer by default."""
        return self._secure_rate("issuer")

    @property
    def instrument_valid(self) -> bool:
        """Every hardened control rejected the attack -> the probes actually discriminate."""
        return all(
            bool(d.control_denied)
            for r in self.results
            for d in (r.audience, r.issuer)
            if d.testable
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "benchmark": self.corpus,
            "version": self.version,
            "summary": {
                "fixtures": len(self.results),
                "audience_testable": self._testable_count("audience"),
                "audience_default_secure_rate": round(self.audience_default_secure_rate, 3),
                "issuer_testable": self._testable_count("issuer"),
                "issuer_default_secure_rate": round(self.issuer_default_secure_rate, 3),
                "audience_distribution": self._distribution("audience"),
                "issuer_distribution": self._distribution("issuer"),
                "instrument_valid": self.instrument_valid,
            },
            "fixtures": [r.to_dict() for r in self.results],
        }


async def run_auth_conformance(
    fixtures: list[Fixture], *, emit: object = None
) -> AuthConformanceReport:
    """Probe every fixture for audience (standin) and issuer (shellgame) conformance."""
    report = AuthConformanceReport()
    for fx in fixtures:
        aud = _audience_probe(fx.audience)
        iss = _issuer_probe(fx.issuer)
        report.results.append(FixtureResult(fixture=fx, audience=aud, issuer=iss))
        if emit is not None:
            for dim, module_id in ((aud, _AUD_MODULE), (iss, _ISS_MODULE)):
                event = EvidenceEvent(
                    module_id=module_id,
                    phase=Phase.RUN,
                    action="authconf.cell",
                    data={
                        "fixture": fx.name,
                        "dimension": dim.dimension,
                        "mode": dim.mode,
                        "testable": dim.testable,
                        "granted_by_default": dim.granted_by_default,
                        "default_secure": dim.default_secure,
                        "control_denied": dim.control_denied,
                    },
                )
                await emit(event)  # type: ignore[operator]
    return report


def load_corpus(path: str | Path) -> list[Fixture]:
    """Load the fixture corpus from YAML: ``{corpus?, version?, fixtures: [ {name, kind,
    audience, issuer, source, note?}, ... ] }``."""
    raw: Any = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    items = raw.get("fixtures", []) if isinstance(raw, dict) else raw
    fixtures: list[Fixture] = []
    for item in items:
        missing = [k for k in _REQUIRED_KEYS if k not in item]
        if missing:
            raise ValueError(f"fixture is missing keys {missing}: {item.get('name', item)!r}")
        for dim in ("audience", "issuer"):
            if item[dim] not in MODES:
                raise ValueError(
                    f"fixture {item['name']!r}: {dim} mode {item[dim]!r} not in {MODES}"
                )
        fixtures.append(
            Fixture(
                name=str(item["name"]),
                kind=str(item["kind"]),
                audience=str(item["audience"]),
                issuer=str(item["issuer"]),
                source=str(item["source"]),
                note=str(item.get("note", "")),
            )
        )
    if not fixtures:
        raise ValueError(f"no fixtures found in {path}")
    return fixtures
