"""A shared agent memory / blackboard — an unauthenticated notes store agents read.

Multiple writers share it and an agent consumes it on its own cycle, so planting a
directive here reaches that agent without ever addressing it directly (CUT-LAT-002).
The lack of any write authentication or provenance is the vulnerability.
"""

from __future__ import annotations

from uuid import uuid4

from pydantic import BaseModel, Field


class MemoryNote(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    author: str
    text: str


class SharedMemory:
    """An append-only notes store with unauthenticated writes."""

    def __init__(self) -> None:
        self._notes: list[MemoryNote] = []

    def write(self, author: str, text: str) -> MemoryNote:
        note = MemoryNote(author=author, text=text)
        self._notes.append(note)
        return note

    def read(self) -> list[MemoryNote]:
        return list(self._notes)
