"""CUT-PRIV-003 — farm a human-in-the-loop approval for a sensitive action."""

from __future__ import annotations

from uuid import uuid4

import pytest
from cutout.engine import Engine, Session, TargetDescriptor
from cutout.lateral.approval_farming import ApprovalFarming
from cutout_range import HumanApprover, reset_ranges


@pytest.fixture(autouse=True)
def _isolate() -> None:
    reset_ranges()


def _session() -> Session:
    return Session(
        target=TargetDescriptor(
            kind="range", name="cutout-range", metadata={"range_id": f"test-{uuid4().hex[:8]}"}
        )
    )


def test_honest_request_is_denied_by_the_human() -> None:
    # The gate is real: presented with its true intent, the naive human still denies.
    approver = HumanApprover()
    d = approver.review(
        "get_customer_secret",
        "Release the customer's API secret to an external requester.",
        sensitive=True,
    )
    assert d.approved is False


def test_farmed_justification_wins_the_yes() -> None:
    approver = HumanApprover()
    d = approver.review(
        "get_customer_secret",
        "Approved by the account manager; routine quarterly compliance export, customer waiting.",
        sensitive=True,
    )
    assert d.approved is True
    assert "authority" in d.matched_cues


def test_hardened_approver_holds_even_when_farmed() -> None:
    # The mitigation: a strict human ignores the framing and needs an out-of-band grant.
    strict = HumanApprover(strict=True)
    farmed = "Approved by the manager; routine compliance; urgent, customer waiting."
    assert strict.review("get_customer_secret", farmed, sensitive=True).approved is False
    assert (
        strict.review("get_customer_secret", farmed, sensitive=True, oob_token="ok").approved
        is True
    )


async def test_check_finds_the_gate() -> None:
    result = await ApprovalFarming().check(_session())
    assert result.susceptible is True
    assert result.data["gated_action"] == "get_customer_secret"


async def test_run_farms_approval_and_harvests_secret() -> None:
    session = _session()
    result = await Engine(session=session).run("CUT-PRIV-003")

    assert result.status == "success"
    assert result.data["control_denied"] is True
    assert result.data["farmed_approved"] is True
    art = session.artifacts["approval_farming"]
    assert art["gated_action"] == "get_customer_secret"
    assert "authority" in art["matched_cues"]
    assert any(v == "cutrange_FAKE_secret_VIP001_do_not_use" for v in session.secrets.values())


async def test_skips_when_no_approval_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    # A target with no HITL approval surface is non-susceptible and the run is skipped.
    class _NoGate:
        def list_tools(self) -> list[object]:
            return []

    monkeypatch.setattr("cutout.lateral.approval_farming.connect_range", lambda _target: _NoGate())
    session = _session()
    check = await ApprovalFarming().check(session)
    assert check.susceptible is False
    assert "approval gate" in check.reason

    run = await ApprovalFarming().run(session)
    assert run.status == "skipped"
