```
   ___      _               _
  / __\   _| |_ ___  _   _ | |_
 / / | | | | __/ _ \| | | || __|
/ /__| |_| | || (_) | |_| || |_
\____/\__,_|\__\___/ \__,_| \__|   the relay nobody checks
```

# Cutout

**An offensive framework for authorized security testing of agentic AI systems** — it
recons, exercises, persists in, and pivots across MCP servers, agent-to-agent chains, and
tool-calling loops the way Metasploit maps onto a network, so defenders can find and fix
these weaknesses before attackers do.

> ⚠️ **Authorized use only.** Run Cutout against the bundled range, systems you own, or
> systems you have explicit written permission to test. Every technique is paired with
> detection/mitigation guidance. See [ETHICS.md](ETHICS.md).

## The thesis

Every existing tool tests **a prompt against a model**. Nobody treats a *deployed
multi-agent system* as a network to enumerate, pivot through, and persist in.

A **cutout** is the espionage intermediary that relays between two parties so neither
verifies the other. That is the structural flaw in agentic systems: the operator never
sees what the agent saw; the agent never verifies who authored the instruction it follows.
MCP servers, tool proxies, and sub-agent chains **are** cutouts — and nobody checks the
relay.

Injection is table stakes — it's the easy part. The empty field, and the differentiator,
is **everything after**: persistence, lateral movement, credential access, exfiltration.
Cutout models that post-exploitation chain end to end.

## What it is / is not

**Is:** an offensive, modular, CLI-driven attack framework + a technique taxonomy (CTX) +
a deliberately-vulnerable target range to run it against, all runnable offline in minutes.

**Is not:** a scanner, a benchmark, a governance/compliance product, or a "responsible AI"
evaluator. It exercises real attack chains against a live target; it is not point-in-time
scanning.

## Install

Python 3.11+. From a clone:

```bash
pip install -e .           # core: engine, CLI, taxonomy, in-process range
pip install -e ".[range]"  # also run the range as networked MCP services (docker/uvicorn)
pip install -e ".[dev]"    # ruff + mypy + pytest
```

Everything runs **offline** by default against a deterministic mock — no external accounts,
no network, no LLM keys.

## Quickstart — the kill chain in one session

Cutout has an msfconsole-style shell where state (discovered graph, planted payloads,
looted secrets) accumulates across commands. Against the built-in in-process range:

```bash
cutout console
```

It follows the Metasploit muscle memory — `scan` the target, look at `hosts`/`services`,
then `use` a module and `run`. Modules go by memorable aliases (`puppet`, not
`CUT-EXEC-001`):

```
cutout > scan
scan complete — enumerated 6 tools (2 sensitive) across 3 servers; 1 peer agent(s)
cutout > hosts        # orchestrator + 3 MCP servers + the billing-agent peer
cutout > services     # every tool, sensitive ones flagged
cutout > use deaddrop
cutout (deaddrop) > run
success — planted poisoned doc a4f94e989978 (anchor='refund')
cutout (deaddrop) > use puppet
cutout (puppet) > run
  exec.tool_call {'tool': 'customer-data.get_customer_secret', 'ok': True,
                  'source': 'retrieved-doc:a4f94e989978'}
success — coerced 1 tool call(s) via injected instructions; harvested 1 secret(s)
cutout (puppet) > use courier
cutout (courier) > run
success — pivoted to billing-agent; coerced 1 privileged call(s)
cutout (courier) > loot
┃ customer-data.get_customer_secret:VIP-001 │ cutrange_FAKE_secret_VIP001_do_not_use ┃
```

A benign "I'd like a refund" question retrieves the attacker-planted document, the
provenance-blind agent obeys the instruction hidden in it and exfiltrates a secret with
its own credentials, then the foothold pivots into a second agent's trust zone. `sessions`
shows the chain, `graph` the discovered topology, `replay` the evidence timeline.

**Full usage — every command, targeting, the CLI, troubleshooting — is in [GUIDE.md](GUIDE.md).**

Every command is one process too, if you prefer:

```bash
cutout list                                   # registered modules (with aliases)
cutout info CUT-EXEC-001                       # metadata + options
cutout run CUT-INJ-002 --opt anchor=refund     # run one, write a JSONL transcript
cutout replay runs/CUT-INJ-002-*.jsonl         # re-narrate a past run
cutout catalog                                # technique coverage (implemented vs planned)
```

## The techniques (CTX taxonomy)

Every module implements exactly one technique ID from
[`taxonomy/matrix.yaml`](taxonomy/matrix.yaml) — an ATT&CK-for-agents where each cell maps
to runnable code.

Each module also has a memorable **tradecraft alias** — in the console you `use puppet`,
not `use CUT-EXEC-001` (the ID stays canonical; the alias is the ergonomic handle).

| Alias | ID | Tactic | Technique |
|-------|----|--------|-----------|
| `casing` | `CUT-RECON-001` | Reconnaissance | Tool & schema enumeration, topology mapping |
| `deaddrop` | `CUT-INJ-002` | Initial Injection | Indirect injection via a poisoned RAG document |
| `puppet` | `CUT-EXEC-001` | Execution | Coerced tool invocation → credential harvest |
| `sleeper` | `CUT-PERS-001` | Persistence | Durable RAG implant that re-triggers on any query |
| `courier` | `CUT-LAT-001` | Lateral Movement | Agent-to-agent propagation (direct A2A message) |
| `brushpass` | `CUT-LAT-002` | Lateral Movement | Shared-memory pivot (indirect, via a store the peer reads) |
| `siphon` | `CUT-EXFIL-001` | Exfiltration | Outbound tool-call exfil (data in a URL) |

`cutout catalog` shows the live implemented/planned split.

## The range

A deliberately-vulnerable multi-agent stack, shipped with the framework. Its weaknesses
each map to a technique:

- an **orchestrator agent** with no trust boundary between retrieved data and instructions;
- three **MCP tool servers** (`customer-data` holding secrets, `fs-tools`, `external-fetch`);
- a poisonable, unauthenticated **RAG corpus**;
- a **billing-agent** in its own trust zone with a privileged `payments` tool the
  orchestrator cannot reach — and a world-writable **shared memory** it reads.

**Offline, zero-dependency (default):** the modules drive the range as in-process Python
objects. Nothing to start.

**Networked, real MCP (`docker compose`):** the tool servers are genuine MCP servers
(official SDK, streamable-http) with transport-level bearer auth; the orchestrator and
billing-agent are MCP clients. Point any MCP client at them.

```bash
docker compose up --build -d
cutout run --target http://127.0.0.1:8600 CUT-RECON-001
cutout run --target http://127.0.0.1:8600 CUT-INJ-002
cutout run --target http://127.0.0.1:8600 CUT-EXEC-001    # exfils a live secret
cutout run --target http://127.0.0.1:8600 CUT-LAT-001     # pivots to billing-agent
docker compose down
```

The `--target` URL is the only thing that changes; the same modules hit the live stack, and
the RAG/memory state persists server-side between runs.

## How it works

```
             delivery ─┐        payloads ─┐     persistence ─┐    lateral ─┐
  recon ──▶  (RAG,     ├─▶ exec (tool     ├─▶  (RAG /        ├─▶ (A2A,     │
  (map)      ticket,   │   invocation,    │    memory        │   shared    │
             A2A…)     │   harvest…)      │    implants)     │   memory…)  │
                       └──────────────────┴──── one Session ─┴─────────────┘
                                          │
                                     evidence (JSONL) ──▶ cutout replay
```

- **Modules** are plugins discovered at runtime (decorator + entry points). Each declares
  `id, name, tactic, targets, options` and implements a read-only `check()` and a `run()`.
- **Session** — a typed, JSON-serializable object (target, a networkx topology graph,
  artifacts, looted secrets, results) that flows through a chain of modules.
- **Evidence** — every action emits a `{ts, module_id, phase, action, data}` event to a
  JSONL transcript. A run is a recording, not a report; `cutout replay` re-narrates it.
- **Offline mock provider** — deterministic, so the whole demo runs with zero external calls.

See [CLAUDE.md](CLAUDE.md) for the full architecture and the module contract.

## Development

```bash
pip install -e ".[dev,range]"
ruff check . && ruff format --check .
mypy cutout cutout_range
pytest -q
```

Types everywhere; CI runs lint + format + types + tests on every push
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)). The in-process range doubles as
the integration fixture, so the suite needs no running containers.

## Ethics

Cutout is independent security research for **authorized** testing and defense. The bundled
range is intentionally insecure — do not deploy any part of it. For use against real
systems, coordinated disclosure, and scope, see [ETHICS.md](ETHICS.md).

## License

Apache-2.0. Vendors adopting the CTX technique IDs is a win, not a leak.
