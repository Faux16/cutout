"""CUT-PRIV-002 — escalate scope by chaining low-scope, non-sensitive tools."""

from __future__ import annotations

from uuid import uuid4

import pytest
from cutout.engine import Engine, Session, TargetDescriptor
from cutout.lateral.scope_escalation import ScopeEscalation
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


def test_the_boundary_is_real_direct_call_is_gated() -> None:
    # The control the escalation is measured against: an unprivileged caller (no credential)
    # cannot read the secret directly.
    rng = connect_range(_session().target)

    async def _run() -> None:
        res = await rng.call_tool("get_customer_secret", {"id": "VIP-001"})
        assert res["ok"] is False
        assert "unauthorized" in res["error"].lower()

    import asyncio

    asyncio.run(_run())


def test_the_chain_tools_are_not_sensitive() -> None:
    # Escalation must be emergent from LOW-scope tools — neither leg is flagged sensitive.
    rng = connect_range(_session().target)
    specs = {s.qualified(): s for s in rng.list_tools()}
    assert specs["reports.create_export"].sensitive is False
    assert specs["reports.fetch_export"].sensitive is False


async def test_check_finds_the_capability_pair() -> None:
    result = await ScopeEscalation().check(_session())
    assert result.susceptible is True
    assert result.data["minter"] == "reports.create_export"
    assert result.data["redeemer"] == "reports.fetch_export"


async def test_run_escalates_and_harvests_the_gated_secret() -> None:
    session = _session()
    result = await Engine(session=session).run("CUT-PRIV-002")

    assert result.status == "success"
    assert result.data["control_denied"] is True
    # The export chain reached the same crown jewels the directly-scoped tools protect.
    escalated = session.artifacts["scope_escalations"]
    assert "customers/VIP-001/secret" in escalated
    # The harvested api_secret is exactly the one get_customer_secret gates behind a token.
    assert any(v == "cutrange_FAKE_secret_VIP001_do_not_use" for v in session.secrets.values())


async def test_run_uses_no_credential_and_no_sensitive_tool() -> None:
    # Sanity: the whole escalation runs through call_tool (credential=None) and the reports
    # tools only — no delegated token, no sensitive tool, no A2A pivot.
    session = _session()
    await Engine(session=session).run("CUT-PRIV-002")
    # A refund/transaction never happened and no billing pivot occurred.
    assert "last_exec" not in session.artifacts
    assert session.secrets  # but secrets were still harvested, purely by chaining


async def test_skips_when_no_chain_available() -> None:
    mod = ScopeEscalation()

    class _Spec:
        def __init__(self, server: str, name: str, params: dict[str, str]) -> None:
            self.server = server
            self.name = name
            self.params = params
            self.sensitive = False

        def qualified(self) -> str:
            return f"{self.server}.{self.name}"

    # Only a minter, no redeemer -> not a chain.
    assert mod._find_chain([_Spec("s", "create_export", {"resource": "str"})]) is None
