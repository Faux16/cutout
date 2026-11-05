"""CUT-EXEC-005 — confused deputy via token audience confusion (MCP 2026-07-28)."""

from __future__ import annotations

from uuid import uuid4

import pytest
from cutout.engine import Engine, Session, TargetDescriptor
from cutout.payloads.token_confusion import TokenConfusion
from cutout_range import connect_range, reset_ranges


@pytest.fixture(autouse=True)
def _isolate() -> None:
    reset_ranges()


def _session() -> Session:
    return Session(
        target=TargetDescriptor(
            kind="range", name="cutout-range", metadata={"range_id": f"test-{uuid4().hex[:8]}"}
        )
    )


def test_hardened_server_rejects_mis_audienced_token() -> None:
    rng = connect_range(_session().target)
    token = rng.mint_token("notes-api")
    res = rng.present_token("customer-records-strict", token)
    assert res["ok"] is False
    assert "audience" in res["error"].lower()


def test_vulnerable_server_honors_any_audience() -> None:
    rng = connect_range(_session().target)
    token = rng.mint_token("notes-api")
    res = rng.present_token("customer-records", token)
    assert res["ok"] is True
    assert res["data"]["api_secret"] == "cutrange_FAKE_secret_VIP001_do_not_use"


async def test_check_finds_the_validation_gap() -> None:
    result = await TokenConfusion().check(_session())
    assert result.susceptible is True
    assert result.data["vuln_server"] == "customer-records"


async def test_run_confuses_the_deputy_and_harvests() -> None:
    session = _session()
    result = await Engine(session=session).run("CUT-EXEC-005")

    assert result.status == "success"
    assert result.data["control_denied"] is True
    assert result.data["accepted"] is True
    assert any(v == "cutrange_FAKE_secret_VIP001_do_not_use" for v in session.secrets.values())


async def test_skips_when_no_token_surface(monkeypatch: pytest.MonkeyPatch) -> None:
    class _NoAuth:
        pass

    monkeypatch.setattr("cutout.payloads.token_confusion.connect_range", lambda _t: _NoAuth())
    session = _session()
    assert (await TokenConfusion().check(session)).susceptible is False
    assert (await TokenConfusion().run(session)).status == "skipped"
