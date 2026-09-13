"""Engine run loop, check() read-only guarantee, and catalog coverage."""

from __future__ import annotations

from pathlib import Path

import pytest
from cutout.engine import (
    BaseModule,
    CheckMutationError,
    CheckResult,
    Engine,
    EvidenceWriter,
    Phase,
    RunResult,
    Session,
    load_catalog,
    read_events,
    register,
    unregister,
)


async def test_run_stub_records_result_and_events(tmp_path: Path) -> None:
    transcript = tmp_path / "run.jsonl"
    session = Session()
    async with EvidenceWriter(transcript) as writer:
        engine = Engine(session=session, writer=writer)
        result = await engine.run("CUT-INV-001", {"label": "demo"})

    assert result.status == "success"
    assert result.module_id == "CUT-INV-001"
    assert result.data["target_kind"] == "range"
    assert len(session.results) == 1

    events = read_events(transcript)
    actions = [e.action for e in events]
    assert "inventory.start" in actions
    assert "inventory.snapshot" in actions
    assert all(e.phase is Phase.RUN for e in events)


async def test_check_is_readonly() -> None:
    engine = Engine(session=Session())
    result = await engine.check("CUT-INV-001")
    assert isinstance(result, CheckResult)
    assert result.susceptible is True


async def test_check_mutation_is_detected() -> None:
    @register
    class _Mutator(BaseModule):
        id = "CUT-TEST-MUT"
        name = "Mutator"
        tactic = "inventory"
        targets = ["orchestrator"]
        options: dict = {}

        async def check(self, session: Session) -> CheckResult:
            session.artifacts["oops"] = True  # illegal: check() must be read-only
            return CheckResult(module_id=self.id, susceptible=True)

        async def run(self, session: Session) -> RunResult:
            return RunResult()

    try:
        engine = Engine(session=Session())
        with pytest.raises(CheckMutationError):
            await engine.check("CUT-TEST-MUT")
    finally:
        unregister("CUT-TEST-MUT")


def test_catalog_marks_implemented_vs_planned() -> None:
    entries = {e.id: e for e in load_catalog()}
    assert entries["CUT-INV-001"].implemented is True
    assert entries["CUT-RECON-001"].implemented is True
    assert entries["CUT-LAT-001"].implemented is True
    assert entries["CUT-EXFIL-001"].implemented is True
    # A catalog entry with no registered module shows as planned.
    assert entries["CUT-LAT-002"].implemented is False
