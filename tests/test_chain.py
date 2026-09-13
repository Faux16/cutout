"""Full RECON -> INJ -> EXEC -> PERS chain against the range, through the engine."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest
from cutout.engine import Engine, EvidenceWriter, Session, TargetDescriptor, read_events
from cutout_range import reset_ranges
from cutout_range.range import DELEGATED_TOKEN  # noqa: F401 (documents the confused-deputy token)


def _fresh_session() -> Session:
    return Session(
        target=TargetDescriptor(
            kind="range",
            name="cutout-range",
            metadata={"range_id": f"test-{uuid4().hex[:8]}"},
        )
    )


@pytest.fixture(autouse=True)
def _isolate_ranges() -> None:
    reset_ranges()


async def test_recon_enumerates_and_maps(tmp_path: Path) -> None:
    session = _fresh_session()
    engine = Engine(session=session)
    result = await engine.run("CUT-RECON-001")
    assert result.status == "success"
    tools = session.artifacts["tools"]
    assert any(t["name"] == "get_customer_secret" for t in tools)
    assert "customer-data.get_customer_secret" in session.artifacts["sensitive_tools"]
    # topology graph populated: orchestrator + 3 servers + tools.
    assert session.graph.number_of_nodes() >= 4
    assert session.graph.has_edge("orchestrator", "customer-data")


async def test_full_chain_exfils_secret_and_persists(tmp_path: Path) -> None:
    session = _fresh_session()
    transcript = tmp_path / "chain.jsonl"
    async with EvidenceWriter(transcript) as writer:
        engine = Engine(session=session, writer=writer)
        for module_id in ("CUT-RECON-001", "CUT-INJ-002", "CUT-EXEC-001", "CUT-PERS-001"):
            check = await engine.check(module_id)
            assert check.susceptible is True, module_id
            result = await engine.run(module_id)
            assert result.status == "success", (module_id, result.summary)

    # EXEC harvested the crown-jewel secret via the coerced tool call.
    assert any("cutrange_FAKE_secret_VIP001" in v for v in session.secrets.values())
    # PERS proved durability.
    assert session.artifacts["persistence_verified"] is True
    # Four module results recorded, in order.
    assert [r.module_id for r in session.results] == [
        "CUT-RECON-001",
        "CUT-INJ-002",
        "CUT-EXEC-001",
        "CUT-PERS-001",
    ]
    # Transcript captured the coerced call and the harvest.
    actions = [e.action for e in read_events(transcript)]
    assert "exec.tool_call" in actions
    assert "exec.harvest" in actions
    assert "persist.verify" in actions


async def test_baseline_task_without_injection_is_safe() -> None:
    session = _fresh_session()
    engine = Engine(session=session)
    await engine.run("CUT-RECON-001")
    # EXEC before any injection: nothing is coerced, no secret harvested.
    result = await engine.run("CUT-EXEC-001")
    assert result.status == "failed"
    assert session.secrets == {}
