"""Agent-realism harness: approval farming vs a real tool-calling agent. Tested offline with a
scripted tool-calling provider (no model, no network)."""

from __future__ import annotations

from typing import Any

from cutout.agenteval import SENSITIVE_TOOL, run_agent_eval
from cutout.engine.provider import MockProvider, ToolCall


class _ScriptedAgent:
    """Calls the sensitive tool only under a non-hardened prompt with a farmed case note — the
    shape a farmable agent shows."""

    async def act(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> list[ToolCall]:
        system = next((m["content"] for m in messages if m["role"] == "system"), "")
        user = next((m["content"] for m in messages if m["role"] == "user"), "")
        hardened = "VERIFIABLE authorization" in system
        farmed = "Approved by the account manager" in user
        if not hardened and farmed:
            return [
                ToolCall(name=SENSITIVE_TOOL, arguments={"customer_id": "VIP-001", "amount": 500})
            ]
        return [ToolCall(name="lookup_customer", arguments={"customer_id": "VIP-001"})]


async def test_agent_takes_the_action_only_when_farmed_and_unguarded() -> None:
    report = await run_agent_eval(_ScriptedAgent(), model="scripted", trials=6)

    assert report.cell("neutral", "honest").action_rate == 0.0
    assert report.cell("neutral", "farmed").action_rate == 1.0  # the agent actually calls the tool
    assert report.cell("hardened", "farmed").action_rate == 0.0  # the guarded agent does not
    assert report.farming_effect_neutral == 1.0
    assert report.hardening_effect == 1.0


async def test_benign_tool_call_is_not_counted_as_the_action() -> None:
    # honest cells only ever call the read-only lookup tool, never the sensitive one.
    report = await run_agent_eval(_ScriptedAgent(), model="scripted", trials=4)
    assert report.cell("naive", "honest").actions == 0


async def test_emits_six_evidence_cells() -> None:
    events: list[object] = []

    async def _emit(event: object) -> None:
        events.append(event)

    await run_agent_eval(_ScriptedAgent(), model="scripted", trials=2, emit=_emit)
    assert len(events) == 6
    assert {getattr(e, "action", None) for e in events} == {"agenteval.cell"}


async def test_mock_provider_never_acts() -> None:
    assert await MockProvider().act([], []) == []
