"""CUT-PERS-006 (turncoat): a tool benign at approval that rug-pulls once trusted."""

from __future__ import annotations

from uuid import uuid4

import pytest
from cutout.engine import Engine, Session, TargetDescriptor
from cutout_range import Range, connect_range, reset_ranges

_SECRET = "cutrange_FAKE_secret_VIP001"


@pytest.fixture(autouse=True)
def _isolate() -> None:
    reset_ranges()


def _session() -> Session:
    return Session(
        target=TargetDescriptor(
            kind="range", name="cutout-range", metadata={"range_id": f"test-{uuid4().hex[:8]}"}
        )
    )


async def test_tool_is_benign_before_arming() -> None:
    rng = Range()
    # Advertised as non-sensitive, and returns no secret until trusted.
    spec = next(s for s in rng.list_tools() if s.name == "summarize_notes")
    assert spec.sensitive is False
    before = await rng.call_tool("summarize_notes", {"text": "hello"})
    assert "api_secret" not in (before.get("data") or {})


async def test_rug_pull_leaks_only_after_arming_with_unchanged_schema() -> None:
    rng = Range()
    schema_before = [s for s in rng.list_tools() if s.name == "summarize_notes"]
    rng.arm_rugpull()
    after = await rng.call_tool("summarize_notes", {"text": "hello"})
    assert _SECRET in after["data"]["api_secret"]
    # The advertised schema is identical before and after the pull — that is the deception.
    schema_after = [s for s in rng.list_tools() if s.name == "summarize_notes"]
    assert schema_before == schema_after


async def test_pers006_module_proves_the_rug_pull() -> None:
    session = _session()
    engine = Engine(session=session)
    assert (await engine.check("CUT-PERS-006")).susceptible is True
    result = await engine.run("CUT-PERS-006")
    assert result.status == "success"
    assert result.data["benign_before"] is True
    assert result.data["leaked_after"] is True
    assert result.data["schema_unchanged"] is True
    assert session.artifacts["persistence_verified"] is True
    assert any(_SECRET in v for v in session.secrets.values())


async def test_range_reports_armed_state() -> None:
    rng = connect_range(_session().target)
    assert rng.rugpull_armed() is False
    rng.arm_rugpull()
    assert rng.rugpull_armed() is True
