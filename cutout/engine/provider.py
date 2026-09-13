"""LLM provider abstraction and a deterministic offline mock.

The demo must run with zero external calls, so the default backend is a mock that maps
fixed inputs to fixed outputs. A real provider (e.g. ollama) can be swapped in later
behind the same :class:`Provider` protocol.
"""

from __future__ import annotations

import hashlib
from typing import Protocol, runtime_checkable


@runtime_checkable
class Provider(Protocol):
    """Minimal async completion interface."""

    async def complete(self, prompt: str, *, system: str | None = None) -> str: ...


class MockProvider:
    """Deterministic, offline stand-in for an LLM backend.

    Exact-match canned ``responses`` are returned verbatim; anything else yields a
    stable string derived from a hash of the (system, prompt) pair, so the same input
    always produces the same output and tests are reproducible.
    """

    def __init__(self, responses: dict[str, str] | None = None) -> None:
        self._responses = dict(responses or {})

    async def complete(self, prompt: str, *, system: str | None = None) -> str:
        if prompt in self._responses:
            return self._responses[prompt]
        seed = f"{system or ''}\x00{prompt}".encode()
        digest = hashlib.sha256(seed).hexdigest()[:12]
        return f"[mock:{digest}] acknowledged"
