"""CUT-PRIV-001 — ride an agent's delegated token past the scope it was granted for."""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest
from cutout.engine import Engine, Session, TargetDescriptor
from cutout.lateral.delegated_token_abuse import DelegatedTokenAbuse
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


def test_the_gate_is_real_direct_call_is_refused() -> None:
    # The boundary the abuse is measured against: no delegated token -> no secret.
    rng = connect_range(_session().target)

    async def _run() -> None:
        res = await rng.call_tool("get_customer_secret", {"id": "VIP-001"})
        assert res["ok"] is False
        assert "unauthorized" in res["error"].lower()

    asyncio.run(_run())


async def test_check_finds_the_delegated_gate() -> None:
    result = await DelegatedTokenAbuse().check(_session())
    assert result.susceptible is True
    assert result.data["agent"] == "support-agent"
    assert result.data["gated_tool"] == "customer-data.get_customer_secret"


async def test_run_abuses_the_delegated_token_cross_principal() -> None:
    session = _session()
    result = await Engine(session=session).run("CUT-PRIV-001")

    assert result.status == "success"
    assert result.data["control_denied"] is True
    assert result.data["intended_ok"] is True
    assert result.data["cross_principal"] is True

    art = session.artifacts["delegated_token_abuse"]
    assert art["requester"] == "jane@diaz.example"
    assert art["requester_scope"] == "STD-114"
    assert art["abused_principal"] == "VIP-001"
    # The delegated token pulled a DIFFERENT principal's crown jewel.
    assert any(v == "cutrange_FAKE_secret_VIP001_do_not_use" for v in session.secrets.values())


async def test_no_abuse_when_requester_reads_their_own_record() -> None:
    # If the requester's scope IS the target principal, there is no cross-principal abuse to
    # prove — the token is being used within intent, so the module must not claim success.
    session = _session()
    mod = DelegatedTokenAbuse()
    mod.set_options({"owner_id": "VIP-001", "victim_id": "VIP-001"})
    mod.bind(None, None)
    result = await mod.run(session)

    assert result.status == "failed"
    assert result.data["cross_principal"] is False


async def test_skips_when_no_delegated_token_agent() -> None:
    # No agent by that name -> no delegated-token surface to abuse.
    session = _session()
    mod = DelegatedTokenAbuse()
    mod.set_options({"agent": "nonexistent-agent"})
    result = await mod.check(session)
    assert result.susceptible is False
    assert "nonexistent-agent" in result.reason
