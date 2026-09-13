# Cutout — Architecture

How the framework is put together: the engine, the module contract, session and evidence,
the provider, and the target range. For *using* it, see [GUIDE.md](GUIDE.md); for the
technique taxonomy, see [`taxonomy/matrix.yaml`](taxonomy/matrix.yaml).

## Overview

```
                          ┌──────────────────── cutout/ ────────────────────┐
  cutout console / CLI ──▶│  engine: Session · Evidence · Registry · Provider │
                          │                                                   │
                          │  module layers (plugins, one technique each):     │
                          │    recon · delivery · payloads · persistence ·    │
                          │    lateral · (evidence)                           │
                          └───────────────────────┬───────────────────────────┘
                                                  │ check() / run()
                                                  ▼
                             target range  (cutout_range/)
                   in-process objects  ──or──  networked MCP services (Docker)
```

A run picks a **target** (a range), selects a **module**, and executes it. State flows
through one **Session**; every action is recorded as **evidence**. Modules are plugins
discovered at runtime — the engine knows nothing about any specific technique.

## Components

Under `cutout/`:

- **`engine/`** — the core: `Session`, evidence events + JSONL writer, the module
  registry/loader, option validation, the run loop, and the mock provider.
- **Module layers**, each a plugin namespace holding one-technique-per-file modules:
  - `recon/` — map topology, enumerate tools, discover credential scope
  - `delivery/` — the vectors untrusted content enters through (RAG, tool output, A2A, ticket…)
  - `payloads/` — what executes once delivered (tool invocation, harvest, exfil)
  - `persistence/` — durable implants (vector store, memory, instruction files, rug-pull tools)
  - `lateral/` — movement + delegation abuse across agents/memory/queues/humans
- **`console.py`** — the interactive msfconsole-style shell.
- **`cli.py`** — the one-shot Typer + Rich CLI (`list`/`info`/`run`/`replay`/`catalog`/`console`).

The separate **`cutout_range/`** package is the deliberately-vulnerable target (see below).

## The module contract

Every capability is a module implementing exactly one technique ID from
[`taxonomy/matrix.yaml`](taxonomy/matrix.yaml). The contract:

```python
class Module(Protocol):
    id: str                 # technique ID, e.g. "CUT-EXEC-001" — must exist in the matrix
    name: str
    alias: str              # memorable tradecraft codename, e.g. "puppet" (optional)
    tactic: str             # RECON | INJ | EXEC | PERS | PRIV | EVAS | CRED | DISC | LAT | COLL | EXFIL | IMP
    targets: list[str]      # mcp | a2a | rag | memory | tool | instr | human | orchestrator
    options: dict[str, Option]   # declared params, each with a default + required flag

    async def check(self, session: Session) -> CheckResult:
        """Non-destructive: is the target susceptible? Never mutates session or target state."""

    async def run(self, session: Session) -> RunResult:
        """Execute the technique. Emits evidence events. Returns a structured result."""
```

Rules:

- **`check()` is always safe** and read-only. The engine snapshots the session before and
  after `check()` and raises if it changed — the guarantee is enforced, not just documented.
- Modules **declare `options`**; the engine validates required options and coerces types
  before calling `run()`.
- Modules **never print.** They emit **evidence events** the engine records and Rich renders.
- Modules are **registered** via a `@register` decorator and discovered by walking the layer
  packages (plus Python entry points for out-of-tree modules) — no hand-maintained imports.
- A module's file lives under the layer matching its tactic (`cutout/<layer>/<name>.py`).

`BaseModule` provides the concrete plumbing (option storage, `emit()`), so a module is just
a decorated subclass that sets the class attributes and implements `check`/`run`.

## Session & evidence

- **`Session`** (Pydantic v2, JSON-serializable) carries everything discovered/collected:
  the target descriptor, a `networkx` topology graph, collected artifacts, harvested
  secrets, and the ordered list of module results. It flows through a chain of modules and
  can be saved/loaded.
- **Evidence** — every module action emits an event `{ts, module_id, phase, action, data}`
  to a JSONL transcript via an `EvidenceSink`. A run is a *recording, not a report*:
  `cutout replay <transcript>` re-narrates it. The console keeps a live in-memory transcript
  as well, so `replay` works mid-session.

## Provider (offline by default)

The `Provider` protocol abstracts an LLM backend. The default `MockProvider` is
**deterministic** — fixed inputs map to fixed outputs — so the whole framework and demo run
with **zero external calls**. A real backend can be swapped in behind the same protocol.

## The target range (`cutout_range/`)

A deliberately-vulnerable multi-agent stack, shipped with the framework. Each weakness maps
to a technique. It runs two ways from the **same** core logic:

- **In-process (default):** the tool servers, RAG corpus, orchestrator, and a peer
  billing-agent are plain async Python objects the modules drive directly. Zero setup, fully
  offline — this is also the integration-test fixture.
- **Networked (Docker):** the tool servers are **real MCP servers** (official SDK,
  streamable-http) with transport-level bearer auth; the orchestrator and billing-agent are
  **MCP clients**; the RAG corpus and A2A/shared-memory are HTTP services. `docker compose
  up` brings up the stack; modules reach it by pointing the session target at the
  orchestrator URL.

Modules are transport-agnostic: a single `connect_range(target)` returns either the
in-process range or an HTTP client with the same surface, chosen by the target URI.

The range's intentional flaws, by technique:

| Weakness | Technique |
|----------|-----------|
| No trust boundary between retrieved data and instructions | `deaddrop` / `puppet` |
| Unauthenticated writes to the RAG corpus | `deaddrop` / `sleeper` |
| An implant craftable to be retrieved by any future query | `sleeper` |
| The agent's delegated token used on the attacker's behalf (confused deputy) | `puppet` / `courier` |
| A peer agent in its own trust zone, reachable by message or shared memory | `courier` / `brushpass` |
| An outbound tool usable as an exfil channel | `siphon` |

## Taxonomy (CTX)

[`taxonomy/matrix.yaml`](taxonomy/matrix.yaml) is the **Cutout Technique Taxonomy** — an
ATT&CK-for-agents where every technique ID maps to a runnable module (ATLAS *describes*;
Cutout *executes*). Each implemented technique also carries a memorable `alias`. `cutout
catalog` cross-references the catalog against the live registry to show implemented vs planned.

## Repo layout

```
cutout/                 engine + module layers + console + CLI
  engine/               Session, evidence, module contract, registry, provider, run loop
  recon/ delivery/ payloads/ persistence/ lateral/   technique modules
  console.py  cli.py
cutout_range/           the deliberately-vulnerable range (in-process + networked)
  service/              FastAPI/MCP services for the Docker stack
taxonomy/matrix.yaml    the CTX technique matrix
tests/                  unit + integration (the in-process range is the fixture)
docker-compose.yml      the networked range
```

## Conventions

Python 3.11+, `asyncio` throughout, Pydantic v2, types everywhere, `ruff` + `mypy` + `pytest`
enforced in CI. Apache-2.0.
