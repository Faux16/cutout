"""Session and result models — the typed state that flows through a run.

A ``Session`` carries everything discovered/collected during a run and is fully
serializable to and from JSON so a run can be paused, inspected, or handed to another
process. The discovered-structure graph is a ``networkx.DiGraph`` persisted as
node-link JSON.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

import networkx as nx
from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator

RunStatus = Literal["success", "failed", "skipped"]


def _utcnow() -> datetime:
    return datetime.now(UTC)


class TargetDescriptor(BaseModel):
    """The system under test for a run.

    Defaults to the bundled offline range so the framework never reaches out unless a
    caller deliberately points it at an authorized target.
    """

    kind: str = "range"
    name: str = "cutout-range (offline mock)"
    uri: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CheckResult(BaseModel):
    """Outcome of a non-destructive susceptibility probe."""

    module_id: str
    susceptible: bool
    reason: str = ""
    data: dict[str, Any] = Field(default_factory=dict)


class RunResult(BaseModel):
    """What a module returns from ``run()`` (timing/identity added by the engine)."""

    status: RunStatus = "success"
    summary: str = ""
    data: dict[str, Any] = Field(default_factory=dict)


class ModuleResult(BaseModel):
    """A completed module execution as persisted on the session."""

    module_id: str
    status: RunStatus = "success"
    summary: str = ""
    data: dict[str, Any] = Field(default_factory=dict)
    started_at: datetime = Field(default_factory=_utcnow)
    finished_at: datetime = Field(default_factory=_utcnow)

    @classmethod
    def from_run(
        cls,
        module_id: str,
        result: RunResult,
        started_at: datetime,
        finished_at: datetime,
    ) -> ModuleResult:
        return cls(
            module_id=module_id,
            status=result.status,
            summary=result.summary,
            data=result.data,
            started_at=started_at,
            finished_at=finished_at,
        )


class Session(BaseModel):
    """Mutable, serializable state carried across a chain of modules."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    id: str = Field(default_factory=lambda: uuid4().hex)
    created_at: datetime = Field(default_factory=_utcnow)
    target: TargetDescriptor = Field(default_factory=TargetDescriptor)
    graph: nx.DiGraph = Field(default_factory=nx.DiGraph)
    artifacts: dict[str, Any] = Field(default_factory=dict)
    secrets: dict[str, str] = Field(default_factory=dict)
    results: list[ModuleResult] = Field(default_factory=list)

    @field_serializer("graph")
    def _serialize_graph(self, graph: nx.DiGraph) -> dict[str, Any]:
        # edges="edges" pins the modern key name and silences networkx's
        # deprecation of the historical "links" default.
        data: dict[str, Any] = nx.node_link_data(graph, edges="edges")
        return data

    @field_validator("graph", mode="before")
    @classmethod
    def _deserialize_graph(cls, value: Any) -> nx.DiGraph:
        if isinstance(value, nx.DiGraph):
            return value
        if isinstance(value, dict):
            graph = nx.node_link_graph(value, edges="edges")
            if not isinstance(graph, nx.DiGraph):
                graph = nx.DiGraph(graph)
            return graph
        raise TypeError(f"cannot build a DiGraph from {type(value).__name__}")
