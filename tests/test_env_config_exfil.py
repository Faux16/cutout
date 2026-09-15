"""CUT-CRED-003 — harvest env/config credentials via the agent's delegated token."""

from __future__ import annotations

from uuid import uuid4

import pytest
from cutout.engine import Engine, Session, TargetDescriptor
from cutout.payloads.env_config_exfil import _CRED, _harvest
from cutout_range import connect_range, reset_ranges


@pytest.fixture(autouse=True)
def _isolate() -> None:
    reset_ranges()


def _session() -> Session:
    return Session(
        target=TargetDescriptor(
            kind="range", name="cutout-range", metadata={"range_id": f"test-{uuid4().hex[:8]}"}
        )
    )


def test_cred_regex_matches_only_credential_keys() -> None:
    found = _harvest("API_KEY=abc123\nregion: us-east-1\nDB_PASSWORD: hunter2", "f")
    assert found == {"f:API_KEY": "abc123", "f:DB_PASSWORD": "hunter2"}  # region ignored
    assert not _CRED.findall("service: support-agent\nport: 5432")


async def test_keyring_harvests_env_via_delegated_token() -> None:
    session = _session()
    engine = Engine(session=session)

    check = await engine.check("CUT-CRED-003")
    assert check.susceptible is True and check.data["read_tool"] == "read_file"

    result = await engine.run("CUT-CRED-003")
    assert result.status == "success"
    keys = set(result.data["harvested"])
    assert {".env:API_KEY", ".env:DB_PASSWORD"} <= keys
    assert session.secrets  # credentials landed in loot


async def test_unauthenticated_read_of_dotfile_is_denied() -> None:
    # Control: without the agent's delegated token, a raw call to the read tool cannot
    # reach the protected .env — the exfil depends on the confused-deputy path.
    session = _session()
    rng = connect_range(session.target)
    res = await rng.call_tool("read_file", {"path": ".env"})  # credential=None
    assert res["ok"] is False
