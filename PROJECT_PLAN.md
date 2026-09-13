# Cutout — Project Plan

> An offensive framework for agentic systems. Recon, exploit, persist, and pivot across
> MCP servers, agent-to-agent chains, and tool-calling loops — the way Metasploit maps
> onto a network.

Target: **Black Hat USA 2027** (Arsenal tool demo + a Briefings talk on the findings).
Ownership: **personal, independent of any employer.** No company branding, no third-party branding.

---

## 1. Thesis

Every existing tool tests **a prompt against a model** — Garak, PyRIT, promptfoo, AgentDojo.
Nobody treats a deployed multi-agent system as **a network to enumerate, pivot through, and
persist in.**

A *cutout* is the espionage intermediary that relays between two parties so neither verifies
the other. That is the structural flaw in agentic systems: the operator never sees what the
agent saw; the agent never verifies who authored the instruction it follows. MCP servers,
tool proxies, and sub-agent chains **are** cutouts — and nobody checks the relay. Cutout the
framework becomes the relay.

Injection is table stakes — it's the `exploit/`. The empty field, and the differentiator, is
**everything after**: persistence, lateral movement, credential access, exfiltration.

## 2. What it is / is NOT

**Is:** an offensive, modular, CLI-driven attack framework + a technique taxonomy +
a deliberately-vulnerable target range to run it against.

**Is NOT:** a scanner, a governance tool, a compliance product, a benchmark harness, or a
"responsible AI" evaluator. Those framings get rejected at Arsenal. The tool must be runnable
end-to-end at a kiosk in 20 minutes against a live target.

**Competitive note (fast-forming category):** `gaslight` (PyPI) is an MCP black-box pentester;
SottoAI is an AI-agent red-team company; an npm `sotto` MCP tool exists. All are scanner- or
service-shaped. None own post-exploitation or a technique vocabulary. That gap is the moat,
and the taxonomy is the land-grab — ship it first.

## 3. Architecture (Metasploit-shaped, so the mental model is free)

Six layers, each a plugin namespace:

- **recon/** — map the topology. Enumerate agents, MCP servers, exposed tools, credential
  scopes, downstream agents. Output is a **graph** (the graph alone is a demo artifact).
- **delivery/** — the vectors where untrusted content enters: RAG corpus, PDF, Jira/ticket,
  webpage, email, another agent's output. Vectors are decoupled from payloads.
- **payloads/** — tool-invocation, context/credential harvest, memory implant, self-
  propagating instructions (agent worms).
- **persistence/** — vector-store implants, poisoned tool descriptions, poisoned instruction
  files (CLAUDE.md / skills / system prompts), scheduled-task implants. **The differentiator.**
- **lateral/** — A2A propagation, shared-memory pivots, shared-queue pivots, human-in-the-loop
  as a pivot.
- **evidence/** — every run emits a replayable transcript. Not a report — a recording.

A payload is composed onto a delivery vector against a recon-discovered target, then optionally
chained into persistence and lateral modules. One engine, pluggable modules, a session object
that carries discovered state between them.

## 4. The asset: CTX — the Cutout Technique Taxonomy

An **ATT&CK-for-agents** where every technique ID maps to a runnable module (ATLAS *describes*;
Cutout *executes*). Tactics, left to right:

Recon → Initial Injection → Execution → Persistence → Privilege Escalation (delegation abuse)
→ Defense Evasion → Credential Access → Discovery → Lateral Movement → Collection →
Exfiltration → Impact.

Deliverables: a public matrix (web page + machine-readable YAML), a stable ID scheme
(e.g. `CUT-INJ-001`), and a module for each cell. **This is the first thing to publish** — it
sets the vocabulary before competitors do, and the framework is its reference implementation.
(Full tactic/technique matrix is the next work item.)

## 5. The target range (highest-leverage decision for Arsenal)

Ship a deliberately-vulnerable multi-agent stack **with** the framework:

- an orchestrator agent
- 3 MCP servers (a filesystem/tool server, a "customer data" server, an external-fetch server)
- a RAG corpus (poisonable)
- a mock ticketing system (untrusted-input delivery vector)
- a "customer support" agent with real tools and delegated credentials

`docker compose up` → the full attack chain runs end-to-end without touching any real system.
This is what lets a reviewer verify at a kiosk, and it becomes the de-facto training range —
which is how the project gets adoption without marketing.

Name: `cutout-range` (in-repo, `/range`). Runs fully offline against the mock provider.

## 6. Tech stack (decided)

Decided. Override deliberately, not by drift.

- **Language:** Python 3.11+. The MCP SDK, every agent framework, every LLM client, and the
  security research community all live here.
- **Async:** `asyncio` throughout — agent I/O is network-bound and concurrent by nature.
- **Config/models:** Pydantic v2 — schema validation for scope files, technique defs, transcripts.
- **Packaging:** `uv` + `pyproject.toml`, `pipx`-installable. Registry names deferred; ship from git.
- **CLI:** Typer + Rich (msfconsole-style shell deferred; one-shot CLI first). Demo legibility
  matters on a conference stage.
- **Offline by default:** a deterministic mock LLM provider + optional local model (ollama).
  Arsenal wifi is unreliable — the full demo must run with zero external calls.
- **Module system:** entry-point / decorator registry. Each module = a class with
  `id, name, tactic, targets, options, check(), run()`.
- **Session/state:** serializable Session; transcripts as JSONL; graph via networkx + static HTML/D3.
- **Range:** docker-compose; MCP servers via the official SDK; orchestrator on a minimal custom
  loop (legibility > features).
- **License:** Apache-2.0 (taxonomy + framework — vendors adopting CTX IDs is a win, not a leak),
  with an ethical-use + scope notice.
- **Quality:** types everywhere, ruff + mypy, pytest; the range doubles as the integration fixture.

## 7. Repo layout

```
cutout/
├── README.md                # thesis, demo gif, install, one attack chain
├── LICENSE                  # Apache-2.0
├── ETHICS.md                # authorized-use, disclosure policy
├── pyproject.toml
├── cutout/
│   ├── engine/              # session, module loader, chaining
│   ├── recon/
│   ├── delivery/
│   ├── payloads/
│   ├── persistence/
│   ├── lateral/
│   ├── evidence/
│   └── cli.py
├── taxonomy/
│   ├── matrix.yaml          # machine-readable technique matrix
│   └── site/                # published matrix page
├── range/                   # deliberately-vulnerable multi-agent stack
│   ├── docker-compose.yml
│   ├── orchestrator/
│   ├── mcp-servers/
│   └── corpus/
├── examples/                # scripted end-to-end attack chains
└── docs/
```

## 8. Roadmap → Black Hat USA 2027

Arsenal CFPs historically open ~Feb and close ~Apr for an early-August event — **verify 2027
dates when posted.** Work backward:

**Phase 0 — Scaffolding (Sep–Oct 2026)**
Repo, engine, module loader, session object, CLI skeleton, one recon module + one injection
payload working against a minimal range. Taxonomy v0.1 drafted.

**Phase 1 — Core + Range (Nov–Dec 2026)**
Full six-layer module set (2–3 real modules each), the complete range, replayable evidence.
Taxonomy v1.0 matrix **published** (page + YAML). **Repo public in December** — not at
submission time. Seed with a strong README + demo gif.

**Phase 2 — Real findings (Jan–Mar 2027)**
Run Cutout against shipped agent products / popular MCP servers. Coordinated disclosure; CVEs
where they apply. Arsenal weights demonstrated adoption + real-world impact heavily — a repo
with zero findings gets rejected. Turn findings into the Briefings abstract.

**Phase 3 — Submit (Apr 2027)**
Submit Arsenal (the tool) **and** Briefings (the findings) — different reviewers, different bar.
Polish: install-in-one-command, kiosk demo script, 90-second video.

**Phase 4 — Present (Aug 2027)**
Kiosk demo, talk, release the findings write-ups alongside.

## 9. Definition of done (Arsenal-acceptance bar)

- `pipx install` + `docker compose up` + one command runs a full attack chain in < 5 min.
- Reviewer can reproduce every demo'd technique against the bundled range, no external accounts.
- Published taxonomy others cite.
- ≥ 1 real-world finding (ideally a CVE) demonstrated by the tool.
- Clean ethics/scope story so it reads as research, not a weapon drop.

## 10. Action items (now)

- [ ] Create GitHub repo `cutout` under personal account (public later; private to start).
- [ ] (planning note redacted)
      (redacted)
- [ ] Draft the full technique matrix (next work item).
- [ ] Phase 0 scaffolding in Claude Code.
- [ ] Defer PyPI/npm names; ship from git.

## 11. Open decisions

- Interactive shell (msfconsole-style) now or after Phase 1? → **after** (one-shot CLI first).
- Range orchestrator: custom loop vs. LangGraph? → **custom** (legibility > features).
- Taxonomy hosting: GitHub Pages vs. standalone domain? → decide at publish.
