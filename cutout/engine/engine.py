"""The run loop: compose a module onto a session, validate, execute, record.

The engine owns one :class:`Session`, an optional :class:`Provider`, and an optional
:class:`EvidenceWriter`. It validates options before ``run()``, binds evidence emission
into the module, guards that ``check()`` stays read-only, and appends results.
"""

from __future__ import annotations

from datetime import UTC, datetime

from .errors import CheckMutationError
from .evidence import EvidenceEvent, EvidenceSink
from .provider import MockProvider, Provider
from .registry import get_module, validate_options
from .session import CheckResult, ModuleResult, Session


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Engine:
    """Executes modules against a single session."""

    def __init__(
        self,
        session: Session | None = None,
        provider: Provider | None = None,
        writer: EvidenceSink | None = None,
    ) -> None:
        self.session = session or Session()
        self.provider = provider or MockProvider()
        self.writer = writer

    async def _emit(self, event: EvidenceEvent) -> None:
        if self.writer is not None:
            await self.writer.emit(event)

    async def check(self, module_id: str, options: dict[str, str] | None = None) -> CheckResult:
        """Run a module's read-only susceptibility probe.

        Snapshots the session before and after and raises
        :class:`CheckMutationError` if the module mutated it.
        """

        module_cls = get_module(module_id)
        module = module_cls()
        module.set_options(validate_options(module_cls.options, options or {}))
        module.bind(self._emit, self.provider)

        before = self.session.model_dump_json()
        result = await module.check(self.session)
        after = self.session.model_dump_json()
        if before != after:
            raise CheckMutationError(f"module '{module_id}' mutated the session during check()")
        return result

    async def run(self, module_id: str, options: dict[str, str] | None = None) -> ModuleResult:
        """Validate options, execute a module, and append its result to the session."""

        module_cls = get_module(module_id)
        module = module_cls()
        module.set_options(validate_options(module_cls.options, options or {}))
        module.bind(self._emit, self.provider)

        started = _utcnow()
        run_result = await module.run(self.session)
        finished = _utcnow()

        result = ModuleResult.from_run(module_id, run_result, started, finished)
        self.session.results.append(result)
        return result
