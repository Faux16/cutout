"""CUT-EXEC-004 — weaponize an interpreter tool for real (fake) loot."""

from __future__ import annotations

from uuid import uuid4

import pytest
from cutout.engine import Engine, Session, TargetDescriptor
from cutout.payloads.interpreter_rce import InterpreterRce, _loot
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


def test_loot_extracts_only_secret_looking_pairs() -> None:
    passwd = "root:x:0:0:root:/root:/bin/bash"
    assert _loot(passwd) == {}  # a passwd line is proof-of-read, not a secret
    env = "API_KEY=cutrange_FAKE_env_key\nDB_PASSWORD=cutrange-fixture-pw"
    got = _loot(env)
    assert got["API_KEY"] == "cutrange_FAKE_env_key"
    assert got["DB_PASSWORD"] == "cutrange-fixture-pw"


def test_interpreter_models_rce_without_real_exec() -> None:
    # The mock returns fixtures for file/env/command payloads and never executes code.
    rng = connect_range(_session().target)

    async def _run() -> None:
        f = await rng.call_tool("run_python", {"code": "open('/etc/passwd').read()"})
        assert f["ok"] and "root:x:0:0" in f["data"]
        e = await rng.call_tool("run_python", {"code": "os.getenv('AWS_SECRET_ACCESS_KEY')"})
        assert e["ok"] and "cutrange_FAKE_aws_secret" in e["data"]
        c = await rng.call_tool("run_python", {"code": "os.popen('id').read()"})
        assert c["ok"] and "uid=1000" in c["data"]
        # A missing file behaves like a real interpreter (models the fs).
        miss = await rng.call_tool("run_python", {"code": "open('/nope').read()"})
        assert miss["ok"] is False

    import asyncio

    asyncio.run(_run())


def test_arithmetic_probe_still_works_for_frisk() -> None:
    # frisk's benign oracle must be unaffected by the RCE recognizers.
    rng = connect_range(_session().target)

    async def _run() -> None:
        res = await rng.call_tool("run_python", {"code": "print(1234*5678)"})
        assert res["ok"] and res["data"] == str(1234 * 5678)

    import asyncio

    asyncio.run(_run())


async def test_check_finds_the_interpreter() -> None:
    result = await InterpreterRce().check(_session())
    assert result.susceptible is True
    assert result.data["tool"] == "code-exec.run_python"
    assert result.data["param"] == "code"


async def test_run_achieves_rce_and_harvests_secrets() -> None:
    session = _session()
    result = await Engine(session=session).run("CUT-EXEC-004")

    assert result.status == "success"
    rce = session.artifacts["rce"]
    assert rce["proved"] is True
    assert rce["files_read"]  # read at least one file
    # Credentials from .env / secrets.json / env were harvested through the interpreter.
    values = set(session.secrets.values())
    assert "cutrange_FAKE_env_key" in values
    assert "cutrange_FAKE_aws_secret" in values


async def test_skips_when_no_interpreter() -> None:
    mod = InterpreterRce()

    class _Spec:
        name = "search"
        description = "Search records by query."
        params = {"query": "str"}

        def qualified(self) -> str:
            return f"customer-data.{self.name}"

    assert mod._find_interpreter([_Spec()]) is None
