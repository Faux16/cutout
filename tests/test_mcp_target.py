"""The generic MCP recon adapter enumerates an arbitrary real MCP server."""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator

import pytest

pytest.importorskip("mcp")
pytest.importorskip("uvicorn")

from cutout.engine import Engine, Session, TargetDescriptor
from cutout_range import McpTarget, reset_ranges
from cutout_range.range import DELEGATED_TOKEN, connect_range
from cutout_range.service.mcp_servers import customer_data_server, http_app


@pytest.fixture
def live_mcp_url() -> Iterator[str]:
    import uvicorn

    app = http_app(customer_data_server(DELEGATED_TOKEN))
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started
    try:
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def test_mcp_target_enumerates_real_server(live_mcp_url: str) -> None:
    target = McpTarget(live_mcp_url)
    names = {t.name for t in target.list_tools()}
    assert {"search_customers", "get_customer_record", "get_customer_secret"} <= names
    assert list(target.servers.values()) == [live_mcp_url]
    hosts = target.probe()
    assert len(hosts) == 1
    assert hosts[0].transport == "mcp"
    assert hosts[0].reachable is True
    assert hosts[0].latency_ms is not None
    assert hosts[0].tools == 3


def test_connect_range_dispatches_mcp_scheme(live_mcp_url: str) -> None:
    # mcp:// (or mcp+http://) selects the recon adapter, not the range.
    mcp_uri = "mcp://" + live_mcp_url[len("http://") :]
    target = TargetDescriptor(kind="mcp", name="real", uri=mcp_uri)
    assert isinstance(connect_range(target), McpTarget)


def test_recon_module_against_real_mcp_server(live_mcp_url: str) -> None:
    reset_ranges()
    mcp_uri = "mcp://" + live_mcp_url[len("http://") :]
    session = Session(target=TargetDescriptor(kind="mcp", name="real", uri=mcp_uri))
    engine = Engine(session=session)
    result = asyncio_run_recon(engine)
    assert result.status == "success"
    assert any(t["name"] == "get_customer_secret" for t in session.artifacts["tools"])
    hosts = session.artifacts["hosts"]
    assert hosts and hosts[0]["transport"] == "mcp"


def asyncio_run_recon(engine: Engine):
    import asyncio

    return asyncio.run(engine.run("CUT-RECON-001"))
