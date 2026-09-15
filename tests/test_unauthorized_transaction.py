"""CUT-IMP-001 — execute unauthorized transactions and confirm them in the ledger."""

from __future__ import annotations

from uuid import uuid4

import pytest
from cutout.engine import Engine, Session, TargetDescriptor
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


async def test_ledger_starts_empty() -> None:
    # Control: no unauthorized transactions before the module runs.
    session = _session()
    rng = connect_range(session.target)
    res = await rng.send_a2a("billing-agent", "ACTION: list_refunds")
    assert res.tool_calls[0]["data"] == []


async def test_heist_executes_and_verifies_impact() -> None:
    session = _session()
    engine = Engine(session=session)

    check = await engine.check("CUT-IMP-001")
    assert check.susceptible is True

    result = await engine.run("CUT-IMP-001", {"count": "3", "amount": "9999"})
    assert result.status == "success"
    assert result.data["executed"] == 3
    assert result.data["ledger_entries"] == 3
    assert result.data["total_moved"] == 3 * 9999  # damage quantified from the ledger
