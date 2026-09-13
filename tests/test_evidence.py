"""Evidence writer/reader round-trips over JSONL."""

from __future__ import annotations

from pathlib import Path

from cutout.engine import EvidenceEvent, EvidenceWriter, Phase, read_events


async def test_writer_appends_jsonl_and_reads_back(tmp_path: Path) -> None:
    transcript = tmp_path / "nested" / "run.jsonl"
    async with EvidenceWriter(transcript) as writer:
        await writer.emit(EvidenceEvent(module_id="CUT-INV-001", phase=Phase.RUN, action="start"))
        await writer.emit(
            EvidenceEvent(
                module_id="CUT-INV-001",
                phase=Phase.RUN,
                action="snapshot",
                data={"nodes": 3},
            )
        )

    assert transcript.exists()
    lines = transcript.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2

    events = read_events(transcript)
    assert [e.action for e in events] == ["start", "snapshot"]
    assert events[1].data == {"nodes": 3}
    assert events[0].phase is Phase.RUN


async def test_writer_appends_across_two_sessions(tmp_path: Path) -> None:
    transcript = tmp_path / "run.jsonl"
    async with EvidenceWriter(transcript) as writer:
        await writer.emit(EvidenceEvent(module_id="m", phase=Phase.CHECK, action="a"))
    async with EvidenceWriter(transcript) as writer:
        await writer.emit(EvidenceEvent(module_id="m", phase=Phase.RUN, action="b"))
    assert [e.action for e in read_events(transcript)] == ["a", "b"]
