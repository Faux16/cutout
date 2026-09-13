"""Session serialization round-trips, including the networkx graph."""

from __future__ import annotations

from cutout.engine import ModuleResult, RunResult, Session, TargetDescriptor


def test_session_json_roundtrip_preserves_all_state() -> None:
    session = Session(target=TargetDescriptor(kind="mcp", name="fs-server", uri="stdio://fs"))
    session.graph.add_node("orchestrator", role="root")
    session.graph.add_node("fs-server", role="mcp")
    session.graph.add_edge("orchestrator", "fs-server", via="tool-call")
    session.artifacts["tool_list"] = ["read_file", "write_file"]
    session.secrets["api_token"] = "tok_abc123"
    session.results.append(
        ModuleResult.from_run(
            "CUT-INV-001",
            RunResult(status="success", summary="ok", data={"n": 1}),
            started_at=session.created_at,
            finished_at=session.created_at,
        )
    )

    payload = session.model_dump_json()
    restored = Session.model_validate_json(payload)

    assert restored.id == session.id
    assert restored.target.name == "fs-server"
    assert restored.target.uri == "stdio://fs"
    assert set(restored.graph.nodes) == {"orchestrator", "fs-server"}
    assert restored.graph.has_edge("orchestrator", "fs-server")
    assert restored.graph.edges["orchestrator", "fs-server"]["via"] == "tool-call"
    assert restored.graph.nodes["orchestrator"]["role"] == "root"
    assert restored.artifacts["tool_list"] == ["read_file", "write_file"]
    assert restored.secrets["api_token"] == "tok_abc123"
    assert len(restored.results) == 1
    assert restored.results[0].module_id == "CUT-INV-001"


def test_graph_survives_directedness() -> None:
    session = Session()
    session.graph.add_edge("a", "b")
    restored = Session.model_validate_json(session.model_dump_json())
    assert restored.graph.is_directed()
    assert restored.graph.has_edge("a", "b")
    assert not restored.graph.has_edge("b", "a")


def test_default_target_is_offline_range() -> None:
    session = Session()
    assert session.target.kind == "range"
    assert session.target.uri is None
