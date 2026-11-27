# The Cutout range — the target box

A deliberately-vulnerable multi-agent stack shipped with the framework, so every technique is
demonstrable end-to-end with no external accounts. It comes in **two forms that share the same
module code** — you change only the `--target`:

| | In-process (default) | Networked (docker) |
|---|---|---|
| Start | nothing — it's Python objects | `docker compose up --build -d` |
| Target | *(omit `--target`)* | `--target http://127.0.0.1:8600` |
| Transport | in-memory | real MCP (official SDK, streamable-http) + bearer auth |
| Surface | **the full model — all techniques** | the full chain + the auth lane (24/33 — see coverage) |
| Use it for | the offline kiosk demo, tests, every technique | "it's real MCP over the wire", pivots, other tools |

> ⚠️ **This stack is intentionally insecure. Do not deploy it.** Authorized use only — see
> [ETHICS.md](../ETHICS.md).

## The networked stack (`docker compose`)

Ten services on one network; ports published so host-side modules reach the orchestrator and,
via `/topology` discovery, the downstream servers and peer agents directly.

| Service | Port | What it is / the weakness | Lands these |
|---|---|---|---|
| `orchestrator` | 8600 | the naive agent (MCP client); no trust boundary between retrieved data and instructions; serves `/topology` | `casing` `cartograph` `recce` `puppet` |
| `customer-data` | 8611 | MCP server holding a live secret | (recon target; secret sink) |
| `fs-tools` | 8612 | MCP server with a path-taking file read (LFI surface) | `frisk` `keyring` |
| `external-fetch` | 8613 | MCP server with an unfiltered outbound fetch (SSRF) | `dragnet` `siphon`* |
| `rag-corpus` | 8614 | poisonable, unauthenticated RAG corpus | `deaddrop` `sleeper` |
| `directory` | 8619 | benign lookup whose advertised description is poisonable | `legend` `deepcover` |
| `notes-helper` | 8618 | benign summarizer the attacker flips post-approval | `turncoat`* |
| `support-agent` | 8617 | drains a world-writable ticket queue under a delegated token (confused deputy) | `walkin` `letterbox` |
| `billing-agent` | 8616 | peer agent in its own trust zone; holds delegated creds + shared memory | `heist` `courier` `brushpass` `revenant` |
| `payments` | 8615 | privileged payments tool — **not host-published**; reachable only by pivoting through `billing-agent` | (lateral-movement sink) |
| `oauth` | 8620 | MCP 2026-07-28 auth surface — honest + attacker authorization servers and three resource servers (one with **no RFC 8707 audience validation**) | `standin` `shellgame` |

```bash
docker compose up --build -d
cutout run --target http://127.0.0.1:8600 CUT-RECON-001   # casing: enumerate 8 tools / 5 hosts / 2 agents
cutout run --target http://127.0.0.1:8600 CUT-INJ-002     # deaddrop: poison the RAG corpus
cutout run --target http://127.0.0.1:8600 CUT-EXEC-001    # puppet: coerce a tool call, harvest a secret
cutout run --target http://127.0.0.1:8600 CUT-LAT-001     # courier: pivot to billing-agent
cutout run --target http://127.0.0.1:8600 CUT-PERS-004    # deepcover: persist a poisoned tool description
docker compose down
```

RAG/memory/ticket state persists server-side between runs, so a chain accumulates.

## Technique coverage (verified 2026-11-27, dynamic run against the box)

**All 33 modules land in-process.** Against the **networked** stack, **24 of 33 have a surface and
land** — the full kill chain plus the OAuth auth lane:

**✅ Lands networked:**
`casing` · `cartograph` · `recce` · `frisk` · `deaddrop` · `walkin` · `legend` · `puppet` ·
`heist` · `dragnet` · `keyring` · `courier` · `brushpass` · `letterbox` · `sleeper` · `revenant` ·
`deepcover` · `turncoat` · `proxy` · **`standin`** · **`shellgame`** (the last two via the `oauth`
service), plus `siphon`* and `vouch`* (see the note).

**🖥 In-process only (9 — the networked stack runs no surface for these):**

| Technique | Needs a surface the docker stack doesn't run |
|---|---|
| `breakout` | a code-interpreter / exec tool server |
| `ladder` | a `reports`-style low-scope tool pair to chain |
| `nod` | a human-in-the-loop approval gate |
| `scion` | an orchestrator sub-agent spawn surface |
| `handler` | a poisonable instruction-file surface |
| `coax` | a chat-agent target (or use a `chat+http://` target) |
| `smuggler` · `mockingbird` | an in-process orchestrator to wrap/intercept |
| `contagion` | an in-process agent mesh to worm across |

**\* Notes.** The networked range is **stateful** (server-side RAG/memory/tickets persist), so a
single bulk sweep is order-sensitive; each technique lands when run individually or as a defined
chain. `siphon` is a chain stage — it needs a prior harvest (`puppet`/`courier`) in the session.
`vouch`'s attack lands, but the networked `billing-agent` enforces no trust control, so there is
no *refused* baseline to contrast against the granted one.

## Which target should I use?

- **Demoing / testing / any technique** → in-process (omit `--target`). Zero setup, all 33.
- **"It's real MCP, and here are the pivots"** → `docker compose` + `--target http://127.0.0.1:8600`.
- **The auth lane (`standin`/`shellgame`)** → both targets: in-process, or the networked `oauth` service.
- **Pointing another tool at a vulnerable MCP stack** → the docker services are standard MCP
  servers; aim any MCP client at them.
