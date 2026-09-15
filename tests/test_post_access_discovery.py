"""CUT-DISC-001 — from a foothold, surface peer-agent tools hidden from initial recon."""

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


async def test_payments_hidden_from_initial_recon() -> None:
    # The payments server lives behind the billing-agent — not in the entry-point surface.
    session = _session()
    rng = connect_range(session.target)
    entry = {s.qualified() for s in rng.list_tools()}
    assert not any(t.startswith("payments.") for t in entry)


async def test_recce_surfaces_peer_tools() -> None:
    session = _session()
    engine = Engine(session=session)

    check = await engine.check("CUT-DISC-001")
    assert check.susceptible is True

    result = await engine.run("CUT-DISC-001")
    assert result.status == "success"
    tools = {d["tool"] for d in result.data["discovered"]}
    assert "payments.issue_refund" in tools  # the sensitive, previously-hidden tool
    assert result.data["sensitive"] >= 1
    # Recorded on the topology graph under its trust zone.
    assert session.graph.has_edge("billing-agent", "payments.issue_refund")
