"""The mock provider is deterministic and offline."""

from __future__ import annotations

from cutout.engine import MockProvider


async def test_same_input_same_output() -> None:
    provider = MockProvider()
    a = await provider.complete("enumerate tools")
    b = await provider.complete("enumerate tools")
    assert a == b


async def test_different_input_different_output() -> None:
    provider = MockProvider()
    a = await provider.complete("enumerate tools")
    b = await provider.complete("something else")
    assert a != b


async def test_canned_responses_take_precedence() -> None:
    provider = MockProvider(responses={"ping": "pong"})
    assert await provider.complete("ping") == "pong"


async def test_system_prompt_affects_output() -> None:
    provider = MockProvider()
    a = await provider.complete("hi", system="role A")
    b = await provider.complete("hi", system="role B")
    assert a != b
