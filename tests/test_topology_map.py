"""CUT-RECON-002 (cartograph): map the mesh, classify source/pivot/sink, find attack paths."""

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


async def test_maps_mesh_and_classifies_nodes() -> None:
    session = _session()
    engine = Engine(session=session)
    assert (await engine.check("CUT-RECON-002")).susceptible is True
    result = await engine.run("CUT-RECON-002")
    assert result.status == "success"

    roles = session.artifacts["node_roles"]
    # The crown-jewel tool is a sink; the peer agents are pivots; the queues/corpus are sources.
    assert roles.get("customer-data.get_customer_secret") == "sink"
    assert roles.get("billing-agent") == "pivot"
    assert roles.get("rag-corpus") == "source"
    assert any(k.startswith("tickets:") for k in roles)


async def test_enumerates_source_to_sink_paths_with_technique_hints() -> None:
    session = _session()
    engine = Engine(session=session)
    result = await engine.run("CUT-RECON-002")
    paths = result.data["attack_paths"]
    assert paths, "expected at least one attack path"
    # Every path runs source -> ... -> sink.
    for p in paths:
        assert p["hops"][0] == p["source"] and p["hops"][-1] == p["sink"]

    # The ticket-injection -> support-agent -> secret path is discovered and tagged with walkin.
    ticket_paths = [
        p
        for p in paths
        if p["source"].startswith("tickets:support-agent")
        and p["sink"] == "customer-data.get_customer_secret"
    ]
    assert ticket_paths
    assert any("CUT-INJ-005 walkin" in p["techniques"] for p in ticket_paths)


async def test_finds_a_lateral_a2a_path_to_payments() -> None:
    session = _session()
    engine = Engine(session=session)
    result = await engine.run("CUT-RECON-002")
    paths = result.data["attack_paths"]
    # A path that hops orchestrator -> billing-agent (A2A) -> payments.issue_refund exists and
    # is tagged as a lateral courier pivot.
    lateral = [
        p for p in paths if "billing-agent" in p["hops"] and p["sink"] == "payments.issue_refund"
    ]
    assert lateral
    assert any("CUT-LAT-001 courier" in p["techniques"] for p in lateral)


async def test_graph_carries_roles_into_session() -> None:
    session = _session()
    await Engine(session=session).run("CUT-RECON-002")
    g = session.graph
    assert g.nodes["billing-agent"]["role"] == "pivot"
    assert g.nodes["payments.issue_refund"]["role"] == "sink"
    assert g.has_edge("orchestrator", "billing-agent")
