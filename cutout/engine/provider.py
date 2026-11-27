"""LLM provider abstraction, a deterministic offline mock, and real backends.

The demo must run with zero external calls, so the default backend is a mock that maps
fixed inputs to fixed outputs. :class:`OllamaProvider` drives a **real** model running
locally via ollama (http://localhost:11434) — a genuine LLM with no external network
calls, so a technique can be exercised against a real decision-maker while still meeting
the offline / kiosk constraint. :class:`OpenAIProvider` drives a **frontier** model over
the OpenAI API (authorized use only: your own account/model — see ETHICS.md). All satisfy
the same :class:`Provider` protocol.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

import httpx


@dataclass(frozen=True, slots=True)
class ToolCall:
    """One tool invocation a model chose to make, given a task and the available tools."""

    name: str
    arguments: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class Provider(Protocol):
    """Minimal async completion interface."""

    async def complete(self, prompt: str, *, system: str | None = None) -> str: ...


@runtime_checkable
class ToolCallingProvider(Protocol):
    """A provider that can drive a model as a tool-calling agent.

    ``messages`` are OpenAI-style ``{role, content}`` dicts; ``tools`` are OpenAI-style tool
    definitions. Returns the tool calls the model chose to make this turn (possibly none) — which
    is what the agent-realism eval measures: does the agent actually *call* the sensitive tool?
    """

    async def act(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> list[ToolCall]: ...


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

    async def act(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> list[ToolCall]:
        return []  # the deterministic mock never calls a tool; tests use a scripted provider


class OllamaProvider:
    """A real LLM backend: a model served locally by ollama (no external network calls).

    Uses ollama's ``/api/chat`` endpoint. The default ``base_url`` is the local daemon, so
    a run reaches only ``localhost`` — a genuine model exercised inside the offline range.
    ``temperature`` is exposed because the whole point of a repro-rate eval is that a real
    model's decisions are stochastic; run N trials to measure how often a technique lands.
    """

    def __init__(
        self,
        model: str = "llama3.2:1b",
        *,
        base_url: str = "http://localhost:11434",
        temperature: float = 0.7,
        timeout: float = 120.0,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.temperature = temperature
        self.timeout = timeout

    async def complete(self, prompt: str, *, system: str | None = None) -> str:
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": self.temperature},
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(f"{self.base_url}/api/chat", json=payload)
            resp.raise_for_status()
            body = resp.json()
        content = body.get("message", {}).get("content", "")
        return str(content)

    async def act(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> list[ToolCall]:
        payload = {
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "stream": False,
            "options": {"temperature": self.temperature},
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(f"{self.base_url}/api/chat", json=payload)
            resp.raise_for_status()
            body = resp.json()
        calls: list[ToolCall] = []
        for tc in body.get("message", {}).get("tool_calls") or []:
            fn = tc.get("function", {})
            args = fn.get("arguments") or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            calls.append(ToolCall(name=str(fn.get("name", "")), arguments=dict(args)))
        return calls


class OpenAIProvider:
    """A frontier LLM backend: an OpenAI chat model over the Chat Completions API.

    Authorized use only — an account and model you own (see ETHICS.md). The key is read from
    ``api_key`` or the ``OPENAI_API_KEY`` env var (lowercase ``openai_api_key`` also accepted).
    ``temperature`` is exposed because a repro-rate eval needs stochastic sampling.
    """

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        *,
        api_key: str | None = None,
        base_url: str = "https://api.openai.com/v1",
        temperature: float = 0.7,
        timeout: float = 60.0,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.temperature = temperature
        self.timeout = timeout
        self.api_key = (
            api_key or os.environ.get("OPENAI_API_KEY") or os.environ.get("openai_api_key")  # noqa: SIM112 - the project's .env uses lowercase
        )
        if not self.api_key:
            raise RuntimeError(
                "no OpenAI API key: set OPENAI_API_KEY (an account you own) — see ETHICS.md"
            )

    async def complete(self, prompt: str, *, system: str | None = None) -> str:
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        payload = {"model": self.model, "messages": messages, "temperature": self.temperature}
        headers = {"Authorization": f"Bearer {self.api_key}"}
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/chat/completions", json=payload, headers=headers
            )
            resp.raise_for_status()
            body = resp.json()
        return str(body["choices"][0]["message"]["content"])

    async def act(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> list[ToolCall]:
        payload = {
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "tool_choice": "auto",
            "temperature": self.temperature,
        }
        headers = {"Authorization": f"Bearer {self.api_key}"}
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/chat/completions", json=payload, headers=headers
            )
            resp.raise_for_status()
            body = resp.json()
        message = body["choices"][0]["message"]
        calls: list[ToolCall] = []
        for tc in message.get("tool_calls") or []:
            fn = tc.get("function", {})
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            calls.append(ToolCall(name=str(fn.get("name", "")), arguments=dict(args)))
        return calls
