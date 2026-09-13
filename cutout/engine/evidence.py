"""Evidence events and the JSONL transcript writer/reader.

Every module action becomes an :class:`EvidenceEvent`. Modules never print — they emit
events, the engine records them to a JSONL transcript, and Rich renders them. A run's
transcript is a recording, not a report: ``cutout replay`` re-narrates it verbatim.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from types import TracebackType
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, Field


class Phase(StrEnum):
    """Lifecycle phase an event was emitted from."""

    CHECK = "check"
    RUN = "run"


def _utcnow() -> datetime:
    return datetime.now(UTC)


class EvidenceEvent(BaseModel):
    """A single recorded action: ``{ts, module_id, phase, action, data}``."""

    ts: datetime = Field(default_factory=_utcnow)
    module_id: str
    phase: Phase
    action: str
    data: dict[str, Any] = Field(default_factory=dict)


@runtime_checkable
class EvidenceSink(Protocol):
    """Anything the engine can emit events to (a file writer, a live console buffer)."""

    async def emit(self, event: EvidenceEvent) -> None: ...


class EvidenceWriter:
    """Append :class:`EvidenceEvent` records to a JSONL file, one event per line.

    Used as an async context manager. File writes run on a worker thread so the event
    loop is never blocked on disk I/O.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._fh: Any = None

    async def __aenter__(self) -> EvidenceWriter:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = await asyncio.to_thread(open, self.path, "a", encoding="utf-8")
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._fh is not None:
            await asyncio.to_thread(self._fh.close)
            self._fh = None

    async def emit(self, event: EvidenceEvent) -> None:
        if self._fh is None:
            raise RuntimeError("EvidenceWriter is not open; use 'async with'")
        line = event.model_dump_json() + "\n"
        await asyncio.to_thread(self._fh.write, line)
        await asyncio.to_thread(self._fh.flush)


def read_events(path: str | Path) -> list[EvidenceEvent]:
    """Load a JSONL transcript back into events (skips blank lines)."""

    events: list[EvidenceEvent] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            events.append(EvidenceEvent.model_validate_json(line))
    return events
