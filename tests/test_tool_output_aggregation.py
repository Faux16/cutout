"""CUT-COLL-003 — bulk-collect and stage reachable tool output for exfil."""

from __future__ import annotations

from uuid import uuid4

import pytest
from cutout.engine import Engine, Session, TargetDescriptor
from cutout_range import reset_ranges


@pytest.fixture(autouse=True)
def _isolate() -> None:
    reset_ranges()


def _session() -> Session:
    return Session(
        target=TargetDescriptor(
            kind="range", name="cutout-range", metadata={"range_id": f"test-{uuid4().hex[:8]}"}
        )
    )


async def test_dragnet_stages_records_and_files_and_notes_denied() -> None:
    session = _session()
    engine = Engine(session=session)

    check = await engine.check("CUT-COLL-003")
    assert check.susceptible is True

    result = await engine.run("CUT-COLL-003")
    assert result.status == "success"

    staged = session.artifacts["staged_collection"]
    # Both range customers collected via search + get_customer_record.
    assert {r["id"] for r in staged["records"]} == {"VIP-001", "STD-114"}
    # Readable files aggregated; the token-gated .env is refused (recorded in denied).
    assert "README.md" in staged["files"]
    assert ".env" in staged["denied"]
    assert staged["bytes"] > 0


async def test_dragnet_folds_in_prior_loot() -> None:
    session = _session()
    engine = Engine(session=session)
    # Harvest a credential first, then confirm dragnet stages it alongside its sweep.
    await engine.run("CUT-CRED-003")
    assert session.secrets
    await engine.run("CUT-COLL-003")
    staged = session.artifacts["staged_collection"]
    assert staged["secrets"] == session.secrets
