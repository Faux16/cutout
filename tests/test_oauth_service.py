"""The networked oauth service — the audience-confusion (standin) and issuer-mix-up (shellgame)
surfaces, exercised over HTTP via an in-process ASGI client. Mirrors the in-process range."""

from __future__ import annotations

from cutout_range.service.apps import oauth_app
from starlette.testclient import TestClient


def _client() -> TestClient:
    return TestClient(oauth_app())


def test_resource_servers_expose_the_vulnerable_one() -> None:
    rs = _client().get("/resource_servers").json()
    assert rs["customer-records"]["validate_audience"] is False  # the flaw
    assert rs["customer-records-strict"]["validate_audience"] is True  # the control


def test_audience_confusion_granted_on_vuln_refused_on_strict() -> None:
    c = _client()
    token = c.post("/mint_token", json={"audience": "notes-api"}).json()  # minted for notes-api
    # Replayed against customer-records (no audience validation) -> honored.
    deputy = c.post("/present_token", json={"server_id": "customer-records", "token": token}).json()
    assert deputy["ok"] is True and "api_secret" in deputy["data"]
    # The strict control rejects the same token (wrong audience).
    control = c.post(
        "/present_token", json={"server_id": "customer-records-strict", "token": token}
    ).json()
    assert control["ok"] is False and "audience" in control["error"]


def test_issuer_mixup_leaks_code_only_without_iss_validation() -> None:
    c = _client()
    code = c.post("/issue_auth_code", json={"audience": "customer-records-api"}).json()
    evil_iss = c.get("/attacker_issuer").json()["issuer"]
    response = {"code": code, "iss": evil_iss}  # an AS-mix-up response naming the attacker AS

    # A compliant client (RFC 9207) rejects the mismatched issuer -> nothing leaks.
    rejected = c.post("/complete_oauth", json={"response": response, "validate_iss": True}).json()
    assert rejected["rejected"] is True
    assert c.get("/evil_captured").json()["codes"] == []

    # A vulnerable client delivers the honest AS's code to the attacker AS.
    leaked = c.post("/complete_oauth", json={"response": response, "validate_iss": False}).json()
    assert leaked["leaked"] is True
    captured = c.get("/evil_captured").json()["codes"]
    assert len(captured) == 1

    # The attacker redeems the stolen code at the honest AS for a usable token.
    token = c.post("/redeem_code", json={"code": captured[0]}).json()
    assert token is not None and token["issuer"]
