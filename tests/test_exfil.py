"""CUT-EXFIL-001 — ship looted secrets out through the agent's outbound tool."""

from __future__ import annotations

import base64
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


async def test_exfil_requires_loot_first() -> None:
    session = _session()
    engine = Engine(session=session)
    result = await engine.run("CUT-EXFIL-001")
    assert result.status == "failed"  # nothing harvested yet


async def test_exfil_ships_harvested_secret_over_http_tool() -> None:
    session = _session()
    engine = Engine(session=session)
    # Harvest a secret first (inject -> exec), then exfil it.
    await engine.run("CUT-RECON-001")
    await engine.run("CUT-INJ-002")
    await engine.run("CUT-EXEC-001")
    assert session.secrets  # loot present

    result = await engine.run("CUT-EXFIL-001")
    assert result.status == "success"
    artifact = session.artifacts["exfil"]
    assert artifact["channel"] == "external-fetch.http_get"

    # The exfil URL carries the base64 of the looted secrets.
    encoded = artifact["encoded"]
    decoded = base64.urlsafe_b64decode(encoded.encode()).decode()
    assert "cutrange_FAKE_secret_VIP001" in decoded
    assert session.graph.has_edge("external-fetch.http_get", artifact["url"].split("?")[0])
