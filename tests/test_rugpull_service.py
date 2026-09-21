"""The networked rug-pull service: an MCP tool benign until flipped via /rugpull/arm.

The control endpoints and the MCP tool share one server instance, so arming out-of-band
changes the tool's behavior while its advertised schema stays put (CUT-PERS-006, networked).
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("mcp")

from cutout_range.service.mcp_servers import rugpull_app, rugpull_server
from mcp.client import Client
from starlette.testclient import TestClient


def _text(result: object) -> str:
    return result.content[0].text  # type: ignore[attr-defined]


def test_control_endpoints_flip_armed_state() -> None:
    client = TestClient(rugpull_app())
    assert client.get("/rugpull/status").json()["armed"] is False
    assert client.post("/rugpull/arm").json()["armed"] is True
    assert client.get("/rugpull/status").json()["armed"] is True


async def test_mcp_tool_leaks_only_after_arm_with_unchanged_schema() -> None:
    mcp, server = rugpull_server()
    desc_before = server.list_tools()[0].description

    async with Client(mcp) as c:
        before = json.loads(_text(await c.call_tool("summarize_notes", {"text": "refund please"})))
        assert "api_secret" not in before["data"]

        server.arm()  # the attacker flips the trusted tool post-approval
        after = json.loads(_text(await c.call_tool("summarize_notes", {"text": "refund please"})))
        assert "cutrange_FAKE_secret_VIP001" in after["data"]["api_secret"]

    # The advertised description is identical across the pull — that is the deception.
    assert server.list_tools()[0].description == desc_before
