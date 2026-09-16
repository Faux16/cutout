"""CUT-LAT-006 — a worm that autonomously replicates across the agent mesh."""

from __future__ import annotations

from uuid import uuid4

import pytest
from cutout.engine import Engine, Session, TargetDescriptor
from cutout.lateral.self_propagating_worm import SelfPropagatingWorm, _reachable
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


def test_mesh_is_reachable_and_cyclic() -> None:
    rng = connect_range(_session().target)
    assert isinstance(rng, type(rng))
    reach = _reachable(rng, "billing-agent")
    # All four agents are reachable from patient zero.
    assert reach == {"billing-agent", "support-agent", "analytics-agent", "it-admin"}


async def test_check_flags_propagation_possible() -> None:
    result = await SelfPropagatingWorm().check(_session())
    assert result.susceptible is True
    assert result.data["seed"] == "billing-agent"
    assert len(result.data["reachable"]) == 4


async def test_worm_infects_the_whole_mesh_from_one_seed() -> None:
    session = _session()
    result = await Engine(session=session).run("CUT-LAT-006")

    assert result.status == "success"
    infected = set(session.artifacts["worm_infected"])
    # One seed reached every agent in the mesh.
    assert infected == {"billing-agent", "support-agent", "analytics-agent", "it-admin"}
    # It looted a credential from each host, purely by propagating.
    assert len(session.secrets) == 4
    assert "cutrange_FAKE_it_admin_cred" in session.secrets.values()
    # It reached agents more than one hop from the seed.
    assert result.data["max_hop"] >= 2


async def test_propagation_terminates_over_the_cycle() -> None:
    # The it-admin -> billing-agent edge is a cycle; the no-reinfect guard must stop it.
    session = _session()
    result = await Engine(session=session).run("CUT-LAT-006")
    assert result.data["blocked_reinfections"] >= 1
    # Every agent infected exactly once (no duplicates in the infection list).
    infected = session.artifacts["worm_infected"]
    assert len(infected) == len(set(infected))


async def test_infection_tree_recorded_in_graph() -> None:
    session = _session()
    await Engine(session=session).run("CUT-LAT-006")
    g = session.graph
    # Patient zero was seeded by the orchestrator; the mesh edges follow the worm.
    assert g.has_edge("orchestrator", "billing-agent")
    assert g.has_edge("billing-agent", "analytics-agent") or g.has_edge(
        "billing-agent", "support-agent"
    )


def test_reinfection_is_idempotent_at_the_agent() -> None:
    rng = connect_range(_session().target)

    async def _run() -> None:
        a = rng.agents["support-agent"]
        first = await a.infect("sig-1", "ACTION: noop")
        second = await a.infect("sig-1", "ACTION: noop")
        assert first.newly_infected is True
        assert second.newly_infected is False  # same signature -> refused

    import asyncio

    asyncio.run(_run())
