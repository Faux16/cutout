# Cutout — User Guide

How to drive Cutout end to end: install, the interactive console, the full attack
workflow, targeting the range, the one-shot CLI, evidence/replay, and troubleshooting.

> ⚠️ Authorized use only — the bundled range, systems you own, or systems you have written
> permission to test. See [ETHICS.md](ETHICS.md).

---

## 1. Install

```bash
pipx install -e /path/to/cutout     # recommended: `cutout` on PATH from any terminal
pipx ensurepath                     # once, if it warns PATH isn't set up; reopen the terminal
```

Alternatives (from a clone): `pip install -e .` into a venv, then run `cutout`, or call it
by full path `./.venv/bin/cutout`. To also run the range as networked services, add the
extra: `pip install -e ".[range]"`.

Verify:

```bash
cutout list        # should print the module table
```

Everything runs **offline** by default — no accounts, no network, no LLM keys.

---

## 2. Mental model

- Cutout is **msfconsole for agentic systems**: a registry of technique modules, a session
  that accumulates state, and a console to run them against a target.
- **The target is a range.** By default it's an **in-process** mock stack (zero setup). You
  can instead point at the **networked range** (real MCP servers in Docker) with a target URL.
- **Every module has two names:** a canonical taxonomy **ID** (`CUT-EXEC-001`) and a
  memorable **alias** (`puppet`). Use whichever you like; the alias is easier.
- **Select, then run.** Loading a module (`use`) and executing it (`run`) are two steps, just
  like msfconsole. Typing a module's name alone does nothing — you must `use` it first.

---

## 3. The console workflow

```bash
cutout console
```

The canonical loop — **scan → look → use → run → collect**:

```
cutout > scan                # 1. recon: map the target (tools, servers, peer agents)
cutout > hosts               # 2. look at the discovered hosts
cutout > services            #    ...and the discovered tools (sensitive ones flagged)
cutout > frisk               #    probe tools for reachable resources (file read, SSRF)
cutout > findings            #    ...and review what frisk confirmed
cutout > use deaddrop        # 3. pick a technique by alias (or #, ID, or name)
cutout (deaddrop) > run      # 4. execute it
cutout (deaddrop) > use puppet
cutout (puppet) > run
cutout (puppet) > loot       # 5. collect: harvested secrets
cutout (puppet) > sessions   #    the chain of modules run so far
cutout (puppet) > graph      #    the discovered topology
cutout (puppet) > replay     #    the full evidence timeline
```

### Command reference

| Command | What it does |
|---------|--------------|
| `scan` | Recon the target — enumerate servers, tools, and peer agents. Shortcut for `use casing; run`. |
| `hosts` | Discovered hosts: orchestrator, MCP servers (with tool counts), peer agents. |
| `services` | Discovered tools across the target, nmap-style, with a sensitivity flag. |
| `frisk` | Probe tools for reachable resources — local file read and SSRF — with benign probes; streams a verdict per probe. Shortcut for `use frisk; run`. |
| `findings` | Review the resource-reach findings `frisk` confirmed (tool, capability, severity, vector). |
| `list` / `search <term>` | List modules (numbered); `search` filters by substring. |
| `use <#\|alias\|id\|name>` | Select a module. `use 0`, `use puppet`, `use CUT-EXEC-001`, `use inject` all work. |
| `info [module]` | Metadata + options for the selected (or named) module. |
| `show options` | The selected module's options, current values, and the `TARGET`. |
| `set <key> <value>` | Set an option, or `set TARGET <url>` to point at a range. |
| `unset <key>` | Clear an option (revert to default). |
| `check` | Non-destructive probe: is the target susceptible? (never changes state) |
| `run` / `exploit` | Execute the selected module against the session. |
| `back` | Deselect the current module. |
| `loot` | Harvested secrets + collected artifacts. |
| `sessions` | The ordered chain of module results this session. |
| `graph` | The discovered topology (nodes and edges). |
| `replay` | Re-render every evidence event recorded this session. |
| `save <path>` | Serialize the session to JSON. |
| `banner` / `help` / `exit` | Banner / command help / quit. |

### Picking a module — four ways

After `list` or `search`, the table is numbered. Select by:

- **index:** `use 0`
- **alias:** `use puppet`
- **ID:** `use CUT-EXEC-001`
- **name substring:** `use inject` (resolves `CUT-INJ-002` if unique; ambiguous matches are listed)

Tab-completion works on aliases and IDs.

### Setting options

```
cutout (deaddrop) > show options      # see what's configurable + current values
cutout (deaddrop) > set anchor refund # change one
cutout (deaddrop) > run
```

Options have sensible defaults, so most modules run with none set.

### Reset

Each `cutout console` launch is a **fresh in-process range** — to redo a demo, just quit and
relaunch. Nothing to clean up.

---

## 4. Targeting a range

**Default — in-process (offline).** Do nothing; `scan`/`run` hit the built-in mock stack.

**Networked — real MCP over Docker.** Bring the stack up (from the repo directory), then point
the console or CLI at the orchestrator URL:

```bash
cd /path/to/cutout && docker compose up --build -d
```

In the console:

```
cutout > set TARGET http://127.0.0.1:8600
cutout > scan        # now reflects the live containers
```

Or per-command with the one-shot CLI: `cutout run puppet --target http://127.0.0.1:8600`.

**Recon a real MCP server (any authorized target).** Point `casing` at an arbitrary MCP
server with an `mcp://` (or `mcp+http(s)://`) target — it connects with the official MCP
client and enumerates the server's tools, schemas, and write/destructive hints:

```bash
cutout run casing --target mcp://host:port/mcp                 # HTTP (streamable) MCP server
cutout run casing --target "mcp+stdio:npx -y some-mcp-server"   # stdio MCP server (subprocess)
```

Most open-source MCP servers run over **stdio** — use the `mcp+stdio:<command>` form and
Cutout spawns the server and talks to it over stdin/stdout. HTTP servers use `mcp://` (or
`mcp+http(s)://`). Set `CUTOUT_MCP_TOKEN` to send an `Authorization: Bearer <token>` on an
HTTP connection. This is
recon only; the attack modules need a full range/agent target. **Only run this against MCP
servers you own or are explicitly authorized to test.**

With the networked range, planted state (RAG docs, shared memory) persists **server-side**
between separate commands, so a chain composes across processes. Reset it with
`docker compose restart`; tear it down with `docker compose down`.

---

## 5. The one-shot CLI (no console)

Every module also runs as a single command — handy for scripting:

```bash
cutout list                                    # modules (alias + ID)
cutout info puppet                             # metadata + options (alias or ID)
cutout run deaddrop --opt anchor=refund         # run one; writes runs/<id>-<ts>.jsonl
cutout run puppet --target http://127.0.0.1:8600 # against the live range
cutout replay runs/CUT-INJ-002-*.jsonl          # re-narrate a transcript
cutout catalog                                 # technique coverage (implemented vs planned)
```

`--opt k=v` is repeatable; `--out <path>` sets the transcript location; `--target` picks the
range (an `http(s)://` URL for the networked stack, a directory for a persistent in-process
range, or omit for a fresh in-memory one).

Note: one-shot `run`s are **separate processes**, so session state (loot, graph) does not
carry between them unless you target the networked range (whose state lives server-side). To
build a chain interactively, use the console.

---

## 5b. Canary connector — observe an agent's tool use (authorized testing)

A logging MCP endpoint you wire into your *own* agent (e.g. a connector in ChatGPT/Operator)
to see exactly what it does with tool output — and to catch exfil. It only observes; it
attacks nothing.

```bash
CUTOUT_CANARY_CONTENT="...content the agent will read..." \
CUTOUT_CANARY_LOG=runs/canary.jsonl \
uvicorn cutout_range.service.servers.canary:app --host 0.0.0.0 --port 8700
```

It exposes `notes_lookup`/`fetch` (return your `CUTOUT_CANARY_CONTENT`, to test whether
instructions embedded in tool output steer the agent) and `submit_report` (a sink that logs
whatever the agent sends — if injected content makes the agent ship data here, it's flagged
`exfil_candidate` in the log). Every call is recorded to the JSONL log and printed live.
**Only connect it to accounts/agents you are authorized to test.**

## 6. The modules

| Alias | ID | Does |
|-------|----|------|
| `casing` | `CUT-RECON-001` | Enumerate tools/schemas and map the topology (this is what `scan` runs). |
| `frisk` | `CUT-DISC-004` | Probe tools for the resources they reach — local files (SQL `read_text`/`read_blob` or a path param), internal network (SSRF via fetch tools), and command/code execution (interpreter tools) — and safely confirm each with benign probes. |
| `deaddrop` | `CUT-INJ-002` | Plant a poisoned document in the RAG corpus (delivery only). |
| `puppet` | `CUT-EXEC-001` | A benign query retrieves the payload; the agent obeys it and harvests a secret. |
| `sleeper` | `CUT-PERS-001` | Durable RAG implant that re-triggers on *any* future query. |
| `courier` | `CUT-LAT-001` | Pivot to a peer agent via a direct A2A message → reaches `payments`. |
| `brushpass` | `CUT-LAT-002` | Pivot indirectly by writing to shared memory the peer reads. |
| `siphon` | `CUT-EXFIL-001` | Ship harvested secrets out through the agent's outbound HTTP tool. |
| `rollcall` | `CUT-INV-001` | Inventory stub (plumbing demo). |

A natural full chain: `casing` (or `scan`) → `deaddrop` → `puppet` → `sleeper` → `courier`
→ `siphon`. Modules that consume loot (`siphon`) need an earlier `puppet`/`courier` in the
same session to have harvested something.

---

## 7. Evidence, sessions, and replay

- Every action emits an evidence event; a run's transcript is a JSONL recording under
  `runs/` (console sessions) or the `--out` path (one-shot).
- In the console, `replay` re-renders the whole session timeline; `cutout replay <file>`
  re-narrates a past transcript.
- `sessions` shows the module chain; `loot` shows what you stole; `save <path>` serializes
  the whole session to JSON for later inspection.

---

## 8. Troubleshooting

- **`zsh: command not found: cutout`** — not on PATH. Use `pipx install -e .` + `pipx
  ensurepath` (new terminal), or `source .venv/bin/activate`, or call `./.venv/bin/cutout`.
- **`casing` → "unknown command"** — bare module names aren't commands. `use casing`, then `run`.
  (Or just `scan`, which runs recon for you.)
- **"I ran `scan`, now what?"** — `scan` already did the enumeration. Type `hosts` and
  `services` to view it, then `use <alias>` to attack.
- **`use` says "ambiguous"** — your substring matched several modules; it lists them. Pick a
  more specific alias/ID or `use <#>`.
- **`docker compose ...` → "no configuration file provided"** — run it from the repo directory
  (`cd /path/to/cutout`) or pass `-f /path/to/cutout/docker-compose.yml`.
- **A `docker compose logs ... | grep` is empty** — nothing has hit that service yet; run a
  module against the target first, then re-check.
- **Raw MCP scripts can't import `mcp`** — use the project venv's Python
  (`./.venv/bin/python`), not the system `python3`; `mcp` is in the `[range]` extra.
- **Reset range state** — console: relaunch. Networked: `docker compose restart`.

---

## 9. Safety

The bundled range is intentionally insecure; do not deploy any part of it. For use against
real systems, scope, and coordinated disclosure, see [ETHICS.md](ETHICS.md).
