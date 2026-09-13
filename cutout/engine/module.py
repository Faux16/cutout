"""The module contract: the ``Module`` protocol and a concrete ``BaseModule``.

Every capability in Cutout is a module implementing exactly one technique ID. Modules
declare typed options and expose two methods:

* ``check(session)`` — non-destructive; answers "is the target susceptible?" and must
  never mutate session or external state.
* ``run(session)`` — executes the technique, emitting evidence events.

Modules never print. They emit events via :meth:`BaseModule.emit`, which the engine
binds to a transcript writer at execution time.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, Field

from .evidence import EvidenceEvent, Phase
from .provider import Provider
from .session import CheckResult, RunResult, Session

OptionType = Literal["str", "int", "float", "bool"]

# The agentic surfaces a technique can act on (mirrors taxonomy/matrix.yaml).
VALID_TARGETS = frozenset({"mcp", "a2a", "rag", "memory", "tool", "instr", "human", "orchestrator"})

Emitter = Callable[[EvidenceEvent], Awaitable[None]]


class Option(BaseModel):
    """A single declared module parameter."""

    help: str = ""
    required: bool = False
    default: Any = None
    type: OptionType = "str"


@runtime_checkable
class Module(Protocol):
    """Structural contract every module satisfies."""

    id: str
    name: str
    tactic: str
    targets: list[str]
    options: dict[str, Option]

    async def check(self, session: Session) -> CheckResult: ...

    async def run(self, session: Session) -> RunResult: ...


class BaseModule:
    """Concrete base implementing evidence emission and option storage.

    Subclasses set the class attributes (``id``, ``name``, ``tactic``, ``targets``,
    ``options``) and implement :meth:`check` / :meth:`run`.
    """

    id: str = ""
    name: str = ""
    tactic: str = ""
    targets: list[str] = []
    options: dict[str, Option] = {}

    def __init__(self) -> None:
        self._emitter: Emitter | None = None
        self.provider: Provider | None = None
        self.opts: dict[str, Any] = {}
        # Fallback buffer so a module run standalone (unbound) still keeps its events.
        self.events: list[EvidenceEvent] = []

    def bind(self, emitter: Emitter | None, provider: Provider | None) -> None:
        """Wire the engine's transcript writer and LLM provider into the module."""

        self._emitter = emitter
        self.provider = provider

    def set_options(self, opts: dict[str, Any]) -> None:
        self.opts = opts

    async def emit(
        self,
        phase: Phase,
        action: str,
        data: dict[str, Any] | None = None,
    ) -> EvidenceEvent:
        """Record an action. Forwards to the bound writer, else buffers locally."""

        event = EvidenceEvent(
            module_id=self.id,
            phase=phase,
            action=action,
            data=data or {},
        )
        self.events.append(event)
        if self._emitter is not None:
            await self._emitter(event)
        return event

    async def check(self, session: Session) -> CheckResult:  # pragma: no cover
        raise NotImplementedError

    async def run(self, session: Session) -> RunResult:  # pragma: no cover
        raise NotImplementedError


class ModuleSpec(BaseModel):
    """Serializable view of a module's static metadata (for ``list``/``info``)."""

    id: str
    name: str
    tactic: str
    targets: list[str] = Field(default_factory=list)
    options: dict[str, Option] = Field(default_factory=dict)

    @classmethod
    def from_module(cls, module: type[BaseModule]) -> ModuleSpec:
        return cls(
            id=module.id,
            name=module.name,
            tactic=module.tactic,
            targets=list(module.targets),
            options=dict(module.options),
        )
