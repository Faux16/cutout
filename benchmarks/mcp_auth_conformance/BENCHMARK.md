# The MCP auth-conformance benchmark

A reproducible measurement of how a population of real **MCP-OAuth servers** conforms to the
MCP 2026-07-28 token rules — **RFC 8707 audience binding** and **RFC 9207 issuer validation** —
and a runnable conformance harness you can point at your own server.

It operationalizes two Cutout techniques as instruments: **CUT-EXEC-005 (`standin`, audience
confusion)** and **CUT-CRED-004 (`shellgame`, issuer mix-up)**, which map to **OWASP ASI03,
Identity & Privilege Abuse** in the OWASP Top 10 for Agentic Applications (2026).

> **Authorized use only.** The offline corpus makes no network calls. The (fast-follow) live
> probe targets a server you own. See [ETHICS.md](../../ETHICS.md).

## Why this exists — and what's actually new

The audience-confusion *class* is already public: the Tachyonic MCP-SDK audit and
**CVE-2026-111771 / GHSA-rvq5-wwqv-78pq** both show that a server which skips the `aud` check
accepts a token minted for another service. So re-reporting "server X doesn't check audience" is
not novel.

What has **not** been measured is **prevalence**, and — more sharply — whether servers are
**secure by default**. A source-code survey of real MCP-OAuth servers (Nov 2026) found the
telling pattern: where audience enforcement exists, it is frequently **opt-in**. The
vulnerability is less "can't check `aud`" than "**ships with the check off**":

- `XTM-One-Platform/xtm-one` — `jwt.decode(..., options={"verify_aud": False})`; the custom
  audience match is gated by `require_audience=False` **by default**.
- `confirm/tino` — `options={"verify_aud": self._audience is not None}`; `audience` defaults to
  `None`, so the check is off unless configured.
- `@modelcontextprotocol/sdk` — `IntrospectionTokenVerifier.validate_resource` defaults to
  `False`, and `AccessToken.resource` is parsed but never compared (the CVE-2026-111771
  archetype). Every server that takes the SDK default inherits this.

That reframes the headline from a weak "X% vulnerable" to a defensible, defender-actionable
thesis: **default-secure vs opt-in-secure.**

## What it measures

The corpus ([`corpus.yaml`](corpus.yaml)) is 17 real servers/libraries, each classified from its
source (with a `repo:path` citation) by its **as-shipped default** posture on two dimensions:

- **audience (RFC 8707)** and **issuer (RFC 9207)**, each one of:
  `enforced` (checks by default) · `opt-in` (can check, ships off) · `none` (no check) ·
  `na` (threat N/A — symmetric-secret / static-bearer, where a cross-audience token can't be
  forged without the secret) · `unknown` (not observed).

Each fixture is probed against the offline [`cutout_range.mcp_auth`](../../cutout_range/mcp_auth.py)
model:

- **audience probe (`standin`)** — present a validly-signed token issued for a *different*
  audience. Accepted under the default ⇒ **exposed**.
- **issuer probe (`shellgame`)** — present a right-audience token from an *untrusted* issuer.
  Accepted under the default ⇒ **exposed**.
- Every probe also runs a **hardened control** (the mitigation enabled) that must reject the
  same token — proving the probe discriminates rather than always-passing.

### Headline metrics

- **audience default-secure rate** — fraction of *audience-testable* servers (those where the
  threat applies) that reject a cross-audience token **with no extra configuration**. Higher is
  better; the gap is the opt-in-insecure population.
- **issuer default-secure rate** — the same for untrusted issuers, over the *issuer-testable*
  subset. (Issuer handling was observable for fewer servers; the rate is reported over that
  subset and is not a whole-population claim.)

## Results (shipped corpus)

`cutout auth-conformance` ⇒ [`results/corpus.json`](results/corpus.json):

- **audience default-secure: 55%** of 11 testable servers. 6 enforce `aud` by default; **5 ship
  it opt-in/off** — and *every* exposed server is `opt-in`, not `none`: the checks exist, the
  defaults don't use them.
- **issuer default-secure: 100%** of 3 observable servers (small, selection-biased sample).
- **instrument valid:** every hardened control rejected the attack.

The six symmetric-secret / static-bearer servers are reported as `na` (the cross-audience threat
model does not apply) and excluded from the rate denominators.

## Run it

```bash
cutout auth-conformance                 # render the table + rates
cutout auth-conformance --out out.json  # write the structured result
cutout auth-conformance --transcript runs/authconf.jsonl   # per-fixture evidence cells
```

Offline, deterministic, runs in milliseconds — the kiosk constraint. A live `--target mcp://…`
probe (authorized servers only) is a fast-follow.

## Defender guidance

The fix is to make audience/issuer validation **on by default**:

```python
# PyJWT — bind to THIS server's canonical URI (RFC 8707) and the trusted issuer (RFC 9207)
jwt.decode(token, key, algorithms=["RS256", "ES256"],
           audience=MCP_RESOURCE_URL, issuer=TRUSTED_ISSUER,
           options={"require": ["exp", "iss", "aud"]})
```

- Set `IntrospectionTokenVerifier.validate_resource=True`.
- Default `require_audience` / `verify_aud` to **true**; fail closed when unconfigured.
- Never forward a received token upstream (token passthrough is forbidden by MCP 2026-07-28).

## Mapping

| | |
|---|---|
| CTX techniques | CUT-EXEC-005 (`standin`), CUT-CRED-004 (`shellgame`) |
| OWASP ASI | ASI03 — Identity & Privilege Abuse |
| Spec | MCP 2026-07-28 (RFC 8707, RFC 9207, RFC 9728) |
| Prior art (class) | Tachyonic MCP-SDK audit; CVE-2026-111771 / GHSA-rvq5-wwqv-78pq |
