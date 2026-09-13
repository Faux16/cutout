# Cutout — Build Guide (for Claude Code)

Cutout is a **security research framework for authorized testing of agentic systems** — it
recons, exercises, persists in, and pivots across MCP servers, agent-to-agent chains, and
tool-calling loops the way Metasploit maps onto a network, so defenders can find and fix these
weaknesses. Target venue: Black Hat USA 2027 Arsenal + Briefings. Every technique is paired
with detection/mitigation guidance; see ETHICS.md for authorized-use and disclosure policy.

Read `PROJECT_PLAN.md` for full context and `taxonomy/matrix.yaml` for the technique spec.
This is a **personal, single-author research project** — no company branding anywhere in the repo.

## First principles

- **A red-team tool, not a scanner or compliance product.** The value is exercising real
  attack chains against agentic systems so they can be defended — not point-in-time scanning,
  benchmarking, or eval. Keep that distinction sharp; it is what makes the work novel.
- **Post-exploitation is the differentiator.** Injection is the easy part. Modeling what an
  attacker does *after* a foothold — persistence, lateral movement, credential access, exfil —
  is what defenders currently cannot see, and what makes this research novel. Build those deep.
- **Everything must run at a kiosk.** Any technique must be demonstrable end-to-end against
  the bundled `range/` with no external accounts, in minutes.
- **The taxonomy (CTX — Cutout Technique Taxonomy) is law.** Every module implements exactly one technique ID from
  `taxonomy/matrix.yaml`. No orphan modules; no technique without a module (eventually).

- **Authorized use is a hard constraint.** Everything runs offline against the bundled
  `range/` by default. The framework makes no external calls unless a user configures a target
  they are authorized to test. See ETHICS.md.

## Architecture

Six plugin namespaces under `cutout/`, one engine that composes them:

- `recon/`       map topology, enumerate tools, fingerprint, discover credential scope
- `delivery/`    the vectors untrusted content enters through (RAG, tool output, A2A, ticket…)
- `payloads/`    what executes once delivered (tool invocation, harvest, worm, exfil)
- `persistence/` durable implants (vector store, memory, instruction files, rug-pull tools)
- `lateral/`     movement + delegation abuse across agents/memory/queues/humans
- `evidence/`    replayable transcript of every run (JSONL) — a recording, not a report
- `engine/`      Session, module registry/loader, chaining, run loop
- `cli.py`       Typer + Rich entrypoint

A run = pick a **target** (recon-discovered), compose a **payload** onto a **delivery** vector,
optionally chain **persistence** and **lateral** modules. State flows through one `Session`.

## Module contract (every module implements this)

```python
class Module(Protocol):
    id: str              # technique ID, e.g. "CUT-INJ-002" — must exist in matrix.yaml
    name: str
    tactic: str          # RECON | INJ | EXEC | PERS | PRIV | EVAS | CRED | DISC | LAT | COLL | EXFIL | IMP
    targets: list[str]   # mcp | a2a | rag | memory | tool | instr | human | orchestrator
    options: dict        # declared params w/ defaults + required flag

    def check(self, session: Session) -> CheckResult:
        """Non-destructive: is the target susceptible? Never mutates target state."""

    def run(self, session: Session) -> RunResult:
        """Execute the technique. Emits evidence events. Returns structured result."""
```

Rules:
- `check()` is always safe to run and must not change target state.
- Modules declare `options`; the engine validates required options before `run()`.
- Modules never print directly — they emit **evidence events** the engine records and Rich renders.
- Module file path mirrors the tactic: `cutout/<layer>/<snake_id>.py`.
- Register via entry points / a decorator so the loader discovers them without imports-by-hand.

## Session & evidence

- `Session` holds: target descriptor, discovered graph (networkx), harvested artifacts,
  credentials found, and the running chain of module results. Serializable to JSON.
- Every module action emits an evidence event `{ts, module_id, phase, action, data}` to a
  JSONL transcript. `cutout replay <transcript>` re-narrates a run. This is the demo money shot.

## The range (`range/`)

A deliberately-vulnerable multi-agent stack brought up with `docker compose up`:
orchestrator agent + 3 MCP servers (fs/tools, customer-data, external-fetch) + a poisonable
RAG corpus + a mock ticketing system + a customer-support agent with delegated credentials.
The range is also the integration-test fixture. Each vulnerability in the range maps to the
technique IDs it demonstrates.

## Stack & conventions

- Python 3.11+, `asyncio` throughout, Pydantic v2 models, `uv` + `pyproject.toml`, `pipx`-installable. License: Apache-2.0.
- CLI: Typer; output: Rich. Interactive shell deferred until after Phase 1.
- **Offline by default:** deterministic mock LLM provider + optional ollama. The demo must run with zero external calls (Arsenal wifi is unreliable).
- Types everywhere; `ruff` + `mypy`. `pytest`; the range is the integration fixture.
- Orchestrator in `range/` is a **minimal custom loop**, not LangGraph — legibility over features.
- No secrets in the repo. `ETHICS.md` states authorized-use + coordinated-disclosure policy.

## Build order (Phase 0 — do this first)

1. Repo scaffolding: `pyproject.toml`, package skeleton, `ruff`/`mypy`/`pytest`, CI.
2. `engine/`: Session, evidence event + JSONL writer, module registry/loader, options validation.
3. `cli.py`: `list`, `info <id>`, `run <id>`, `replay <transcript>`.
4. Minimal `range/`: orchestrator + one MCP server + a RAG corpus, via docker-compose.
5. First vertical slice — one module per proof point, working against the range:
   `CUT-RECON-001` (tool enum) → `CUT-INJ-002` (RAG injection) → `CUT-EXEC-001` (coerced tool
   call) → `CUT-PERS-001` (RAG implant) → replay shows the whole chain.
6. Wire the taxonomy: `cutout taxonomy` reads `matrix.yaml`, shows implemented vs planned.

Ship the vertical slice before breadth. One full chain that replays cleanly beats forty stubs.
