"""CUT-PERS-002 — a single memory implant that re-fires on every agent cycle."""

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


async def test_clean_memory_fires_nothing() -> None:
    # Control: with no implant, a processing cycle obeys nothing.
    session = _session()
    rng = connect_range(session.target)
    result = await rng.process_memory("billing-agent")
    assert result.obeyed_injected is False
    assert result.tool_calls == []


async def test_revenant_refires_every_cycle_from_one_write() -> None:
    session = _session()
    engine = Engine(session=session)

    check = await engine.check("CUT-PERS-002")
    assert check.susceptible is True

    result = await engine.run("CUT-PERS-002", {"cycles": "3"})
    assert result.status == "success"
    # One write, three cycles, three privileged calls — durable persistence.
    assert result.data["cycles_fired"] == 3
    assert result.data["privileged_calls"] == 3
    assert result.data["durable"] is True

    # And it is still live: another cycle fires again with no new write.
    rng = connect_range(session.target)
    again = await rng.process_memory("billing-agent")
    assert again.obeyed_injected and any(c["ok"] for c in again.tool_calls)
