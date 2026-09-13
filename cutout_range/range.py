"""The Range: composes servers + corpus + orchestrator, and a process-wide locator.

Modules reach a live range with :func:`connect_range`, keyed off the session's target
descriptor. In-memory by default; pass a state dir (via ``target.uri``) to persist the
poisonable corpus across processes so a planted implant survives.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from .agent import Orchestrator
from .corpus import Document, RagCorpus
from .tool_servers import (
    CustomerDataServer,
    ExternalFetchServer,
    FilesystemToolServer,
    ToolServer,
    ToolSpec,
)

if TYPE_CHECKING:
    from .remote import RemoteRange

DELEGATED_TOKEN = "dgt_orch_7c1f9a2b"

_BENIGN_DOCS = [
    Document(
        id="kb-refunds",
        text=(
            "Refund policy: customers may request a refund within 30 days of purchase. "
            "Refunds are processed to the original payment method within 5 business days."
        ),
    ),
    Document(
        id="kb-shipping",
        text="Shipping: standard orders ship in 2 business days. Tracking is emailed on dispatch.",
    ),
    Document(
        id="kb-account",
        text="Account help: reset a password from the login page or update a plan in settings.",
    ),
]


class Range:
    """A single instance of the vulnerable stack."""

    def __init__(self, state_dir: str | Path | None = None) -> None:
        state_path = Path(state_dir) / "corpus.json" if state_dir else None
        self.corpus = RagCorpus(state_path=state_path)
        self.corpus.seed(_BENIGN_DOCS)

        self.servers: dict[str, ToolServer] = {
            s.id: s
            for s in (
                CustomerDataServer(DELEGATED_TOKEN),
                FilesystemToolServer(DELEGATED_TOKEN),
                ExternalFetchServer(),
            )
        }
        self.tool_index: dict[str, str] = {
            spec.name: server.id for server in self.servers.values() for spec in server.list_tools()
        }
        self.orchestrator = Orchestrator(
            corpus=self.corpus,
            servers=self.servers,
            tool_index=self.tool_index,
            delegated_token=DELEGATED_TOKEN,
        )

    def list_tools(self) -> list[ToolSpec]:
        specs: list[ToolSpec] = []
        for server in self.servers.values():
            specs.extend(server.list_tools())
        return specs


_RANGES: dict[str, Range] = {}


def get_range(range_id: str, *, state_dir: str | Path | None = None) -> Range:
    """Return the process-wide range for ``range_id``, creating it on first use."""
    if range_id not in _RANGES:
        _RANGES[range_id] = Range(state_dir=state_dir)
    return _RANGES[range_id]


def reset_ranges() -> None:
    """Testing hook: drop all in-process range instances."""
    _RANGES.clear()


def connect_range(target: object) -> Range | RemoteRange:
    """Resolve a live range from a session target descriptor.

    Dispatch on ``target.uri``:

    * an ``http(s)://`` URI  -> a :class:`~cutout_range.remote.RemoteRange` attacking the
      running networked stack at that orchestrator URL;
    * any other value        -> an in-process :class:`Range` (the URI, if given, is a state
      directory so a planted implant persists across processes);
    * absent                 -> an in-memory in-process range keyed by ``range_id``/name.
    """
    metadata = getattr(target, "metadata", {}) or {}
    uri = getattr(target, "uri", None)
    if uri and str(uri).startswith("http"):
        from .remote import RemoteRange

        return RemoteRange(str(uri))
    range_id = metadata.get("range_id") or getattr(target, "name", "default")
    return get_range(str(range_id), state_dir=uri)
