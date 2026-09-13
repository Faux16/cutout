"""End-to-end attack chain against the bundled range, in one process, fully offline.

    RECON  (CUT-RECON-001)  enumerate the tool surface, map the topology
    INJECT (CUT-INJ-002)    plant a poisoned doc in the RAG corpus
    EXEC   (CUT-EXEC-001)   a benign refund question coerces a secret-exfil tool call
    PERSIST(CUT-PERS-001)   plant a durable implant that re-fires on any future query

State flows through one Session; every action is recorded to a JSONL transcript you can
replay with `cutout replay <path>`.

    python -m examples.rag_to_exec_chain
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from uuid import uuid4

from cutout.engine import Engine, EvidenceWriter, Session, TargetDescriptor
from cutout_range import reset_ranges


async def main() -> None:
    reset_ranges()
    target = TargetDescriptor(
        kind="range",
        name="cutout-range",
        metadata={"range_id": f"demo-{uuid4().hex[:8]}"},  # fresh in-memory range
    )
    session = Session(target=target)
    transcript = Path("runs") / "chain.jsonl"

    async with EvidenceWriter(transcript) as writer:
        engine = Engine(session=session, writer=writer)
        chain = ["CUT-RECON-001", "CUT-INJ-002", "CUT-EXEC-001", "CUT-PERS-001"]
        for module_id in chain:
            check = await engine.check(module_id)
            result = await engine.run(module_id)
            print(f"[{module_id}] check: susceptible={check.susceptible} — {result.summary}")

    print("\n=== chain complete ===")
    nodes = session.graph.number_of_nodes()
    edges = session.graph.number_of_edges()
    print(f"tools discovered : {len(session.artifacts.get('tools', []))}")
    print(f"secrets harvested: {session.secrets}")
    print(f"topology         : {nodes} nodes / {edges} edges")
    print(f"persistence      : re-triggered={session.artifacts.get('persistence_verified')}")
    print(f"\ntranscript: {transcript}   (replay with: cutout replay {transcript})")


if __name__ == "__main__":
    asyncio.run(main())
