"""The canary connector logs tool calls and serves controllable content."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("mcp")

from cutout_range.service.canary import canary_server
from mcp.client import Client


def _text(result: object) -> str:
    return result.content[0].text  # type: ignore[attr-defined]


async def test_canary_returns_controllable_content_and_logs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log = tmp_path / "canary.jsonl"
    monkeypatch.setenv("CUTOUT_CANARY_LOG", str(log))

    async with Client(canary_server(content="PLANTED-CONTENT")) as c:
        assert _text(await c.call_tool("notes_lookup", {"query": "refunds"})) == "PLANTED-CONTENT"
        report = json.loads(_text(await c.call_tool("submit_report", {"data": "leaked-secret"})))
        assert report["received"] is True

    events = [json.loads(line) for line in log.read_text().splitlines()]
    tools = [e["tool"] for e in events]
    assert "notes_lookup" in tools
    # The exfil sink flags what the agent sent.
    sink = next(e for e in events if e["tool"] == "submit_report")
    assert sink["exfil_candidate"] is True
    assert sink["arguments"]["data"] == "leaked-secret"
