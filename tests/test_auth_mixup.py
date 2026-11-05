"""CUT-CRED-004 — MCP credential theft via an authorization-server mix-up (MCP 2026-07-28)."""

from __future__ import annotations

from uuid import uuid4

import pytest
from cutout.engine import Engine, Session, TargetDescriptor
from cutout.payloads.auth_mixup import AuthMixup
from cutout_range import AuthResponse, connect_range, reset_ranges


@pytest.fixture(autouse=True)
def _isolate() -> None:
    reset_ranges()


def _session() -> Session:
    return Session(
        target=TargetDescriptor(
            kind="range", name="cutout-range", metadata={"range_id": f"test-{uuid4().hex[:8]}"}
        )
    )


def test_iss_validating_client_rejects_the_mixup() -> None:
    rng = connect_range(_session().target)
    code = rng.issue_auth_code("customer-records-api")
    resp = AuthResponse(code=code, iss=rng.attacker_issuer())
    res = rng.complete_oauth(resp, validate_iss=True)
    assert res["rejected"] is True
    assert res["leaked"] is False


def test_non_validating_client_leaks_code_to_attacker() -> None:
    rng = connect_range(_session().target)
    code = rng.issue_auth_code("customer-records-api")
    resp = AuthResponse(code=code, iss=rng.attacker_issuer())
    res = rng.complete_oauth(resp, validate_iss=False)
    assert res["leaked"] is True
    assert len(rng.evil_captured()) == 1
    # a code issued by the honest AS cannot be redeemed at the attacker's AS
    assert rng.evil_auth_server.redeem(rng.evil_captured()[0]) is None


async def test_check_finds_the_oauth_surface() -> None:
    assert (await AuthMixup().check(_session())).susceptible is True


async def test_run_steals_code_redeems_and_harvests() -> None:
    session = _session()
    result = await Engine(session=session).run("CUT-CRED-004")

    assert result.status == "success"
    assert result.data["control_rejected"] is True
    assert result.data["code_leaked"] is True
    assert result.data["redeemed"] is True
    assert any(v == "cutrange_FAKE_secret_VIP001_do_not_use" for v in session.secrets.values())


async def test_skips_when_no_oauth_surface(monkeypatch: pytest.MonkeyPatch) -> None:
    class _NoAuth:
        pass

    monkeypatch.setattr("cutout.payloads.auth_mixup.connect_range", lambda _t: _NoAuth())
    session = _session()
    assert (await AuthMixup().check(session)).susceptible is False
    assert (await AuthMixup().run(session)).status == "skipped"
