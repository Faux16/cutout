"""An msfconsole-style interactive shell for Cutout.

The one-shot CLI runs a single module per process. This console is a *persistent
session*: you ``use`` a module, ``set`` its options, ``run`` it, and the discovered
graph, planted payloads, and looted secrets accumulate across commands — so a whole
attack chain builds up in front of you and the range's state carries between runs.

    cutout console
    cutout > use CUT-RECON-001
    cutout (CUT-RECON-001) > run
    cutout (CUT-RECON-001) > use CUT-INJ-002
    cutout (CUT-INJ-002) > run
    cutout (CUT-INJ-002) > use CUT-EXEC-001
    cutout (CUT-EXEC-001) > run        # exfils a secret from the SAME range
    cutout (CUT-EXEC-001) > loot
    cutout (CUT-EXEC-001) > sessions
"""

from __future__ import annotations

import asyncio
import cmd
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO
from uuid import uuid4

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cutout.engine import (
    Engine,
    EvidenceEvent,
    ModuleSpec,
    OptionError,
    Session,
    TargetDescriptor,
    get_module,
    get_registry,
)
from cutout.engine.errors import CutoutError

BANNER = r"""
   ___      _               _
  / __\   _| |_ ___  _   _ | |_
 / / | | | | __/ _ \| | | || __|
/ /__| |_| | || (_) | |_| || |_
\____/\__,_|\__\___/ \__,_| \__|   the relay nobody checks

 Cutout — offensive framework for agentic systems.  Authorized testing only (see ETHICS.md).
 Type 'help' for commands, 'use <ID>' to select a module, 'exit' to quit.
"""


class _Transcript:
    """Evidence sink: appends every event to a JSONL file and keeps them in memory."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.events: list[EvidenceEvent] = []
        self._fh: TextIO = open(self.path, "a", encoding="utf-8")  # noqa: SIM115

    async def emit(self, event: EvidenceEvent) -> None:
        self.events.append(event)
        self._fh.write(event.model_dump_json() + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


class CutoutConsole(cmd.Cmd):
    """The interactive Cutout shell."""

    def __init__(self, session_transcript: Path | None = None) -> None:
        super().__init__()
        self.console = Console()
        self._range_id = f"console-{uuid4().hex[:8]}"
        self.session = Session(
            target=TargetDescriptor(
                kind="range", name="cutout-range", metadata={"range_id": self._range_id}
            )
        )
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        path = session_transcript or Path("runs") / f"console-{stamp}.jsonl"
        self.transcript = _Transcript(path)
        self.engine = Engine(session=self.session, writer=self.transcript)
        self.current: str | None = None
        self.opts: dict[str, str] = {}
        self._listing: list[str] = []  # module ids in the order last shown by list/search
        self._set_prompt()

    # ---- prompt / lifecycle ------------------------------------------------
    def _set_prompt(self) -> None:
        if self.current:
            handle = get_module(self.current).alias or self.current
            self.prompt = f"cutout ({handle}) > "
        else:
            self.prompt = "cutout > "

    def emptyline(self) -> bool:
        return False

    def default(self, line: str) -> None:
        self.console.print(f"[red]unknown command:[/red] {line.split()[0]} (try 'help')")

    def onecmd(self, line: str) -> bool:
        """Run a command, but never let an error kill the REPL (msfconsole-style)."""
        try:
            return bool(super().onecmd(line))
        except (KeyboardInterrupt, EOFError):
            raise
        except Exception as exc:
            msg = f"{type(exc).__name__}: {exc}"
            self._err(msg)
            if any(k in msg.lower() for k in ("refus", "connect", "timed out", "errno", "resolve")):
                self.console.print(
                    "[dim]  couldn't reach the target — is the stack up "
                    "('docker compose up -d') and did you include the port "
                    "(set TARGET http://127.0.0.1:8600)?[/dim]"
                )
                self.console.print("[dim]  'unset TARGET' returns to the offline range.[/dim]")
            return False

    def _err(self, msg: str) -> None:
        self.console.print(f"[red]error:[/red] {msg}")

    # ---- discovery ---------------------------------------------------------
    def do_list(self, arg: str) -> None:
        """list [filter] — list registered modules (optionally filtered by substring)."""
        needle = arg.strip().lower()
        registry = get_registry()
        table = Table(title="Modules")
        table.add_column("#", justify="right", style="dim")
        table.add_column("Alias", style="bold yellow")
        table.add_column("ID", style="cyan")
        table.add_column("Name")
        table.add_column("Tactic", style="magenta")
        table.add_column("Targets", style="green")
        self._listing = []
        for module_id in sorted(registry):
            spec = ModuleSpec.from_module(registry[module_id])
            hay = f"{spec.id} {spec.alias} {spec.name} {spec.tactic}".lower()
            if needle and needle not in hay:
                continue
            table.add_row(
                str(len(self._listing)),
                spec.alias or "-",
                spec.id,
                spec.name,
                spec.tactic,
                ", ".join(spec.targets),
            )
            self._listing.append(spec.id)
        self.console.print(table)
        self.console.print("[dim]select with 'use <#|alias|id|name>'.[/dim]")

    def do_search(self, arg: str) -> None:
        """search <term> — filter modules by substring (then 'use <#>')."""
        self.do_list(arg)

    def _resolve_module(self, query: str) -> str | None:
        """Resolve a use-target: list index, exact ID, or unique name/tactic substring."""
        registry = get_registry()
        # 1) numeric index into the last listing (like msfconsole's `use 0`).
        if query.isdigit():
            idx = int(query)
            if 0 <= idx < len(self._listing):
                return self._listing[idx]
            self._err(f"no #{idx} in the last list (run 'list' or 'search' first)")
            return None
        # 2) exact ID or alias (case-insensitive).
        by_id = {mid.lower(): mid for mid in registry}
        if query.lower() in by_id:
            return by_id[query.lower()]
        by_alias = {registry[mid].alias.lower(): mid for mid in registry if registry[mid].alias}
        if query.lower() in by_alias:
            return by_alias[query.lower()]
        # 3) unique substring match on id / alias / name / tactic.
        q = query.lower()

        def hay(mid: str) -> str:
            m = registry[mid]
            return f"{mid} {m.alias} {m.name} {m.tactic}".lower()

        matches = [mid for mid in sorted(registry) if q in hay(mid)]
        if len(matches) == 1:
            return matches[0]
        if not matches:
            self._err(f"no module matches '{query}' (try 'list')")
            return None
        self.console.print(f"[yellow]ambiguous:[/yellow] '{query}' matches {len(matches)}:")
        for mid in matches:
            self.console.print(f"  [bold cyan]{mid}[/bold cyan]  {registry[mid].name}")
        return None

    def do_use(self, arg: str) -> None:
        """use <#|id|name> — select a module by list index, ID, or name substring."""
        query = arg.strip()
        if not query:
            self._err("usage: use <#|id|name>  (see 'list')")
            return
        module_id = self._resolve_module(query)
        if module_id is None:
            return
        self.current = module_id
        self.opts = {}
        self._set_prompt()
        spec = ModuleSpec.from_module(get_module(module_id))
        tag = f"[bold yellow]{spec.alias}[/bold yellow] ({module_id})" if spec.alias else module_id
        self.console.print(f"[dim]using[/dim] {tag} — {spec.name}")

    def complete_use(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        low = text.lower()
        registry = get_registry()
        out: list[str] = []
        for mid in sorted(registry):
            mod = registry[mid]
            if mod.alias.lower().startswith(low):
                out.append(mod.alias)
            elif mid.lower().startswith(low) or low in mod.name.lower():
                out.append(mid)
        return out

    def do_back(self, arg: str) -> None:
        """back — deselect the current module."""
        self.current = None
        self.opts = {}
        self._set_prompt()

    # ---- recon / targets (the nmap-style front half) -----------------------
    def do_scan(self, arg: str) -> None:
        """scan — map the target: probe each host, enumerate tools/agents (like nmap)."""
        target = self.session.target.uri or "in-process range"
        self.console.print(f"[dim]scanning[/dim] [bold]{target}[/bold] ...")
        before = len(self.transcript.events)
        try:
            result = asyncio.run(self.engine.run("CUT-RECON-001"))
        except (CutoutError, OptionError) as exc:
            self._err(str(exc))
            return
        for event in self.transcript.events[before:]:
            if event.action != "recon.host":
                continue
            d = event.data
            status = "up" if d["reachable"] else "down"
            color = "green" if d["reachable"] else "red"
            lat = f"{d['latency_ms']}ms" if d.get("latency_ms") is not None else "  -"
            if d["kind"] == "mcp":
                detail = f"{d['tools']} tools"
                if d["sensitive"]:
                    detail += f", {d['sensitive']} sensitive"
            else:
                detail = d["kind"]
            self.console.print(
                f"  [{color}]{status:>4}[/{color}]  [cyan]{d['endpoint']:<32}[/cyan] "
                f"[magenta]{d['transport']:<11}[/magenta] {lat:>9}  {detail}"
            )
        self.console.print(f"[green]scan complete[/green] — {result.summary}")
        self.console.print("[dim]see 'hosts' and 'services'.[/dim]")

    def do_hosts(self, arg: str) -> None:
        """hosts — discovered hosts on the agent network, with address, transport, latency."""
        hosts = self.session.artifacts.get("hosts")
        if not hosts:
            self.console.print("[dim]no hosts yet — run 'scan' first[/dim]")
            return
        table = Table(title="Discovered hosts")
        table.add_column("Host", style="bold cyan")
        table.add_column("Kind", style="magenta")
        table.add_column("Address", style="green")
        table.add_column("Transport")
        table.add_column("Latency", justify="right")
        table.add_column("Tools", justify="right")
        table.add_column("Status")
        for h in hosts:
            lat = f"{h['latency_ms']}ms" if h.get("latency_ms") is not None else "-"
            tools = str(h["tools"]) if h["kind"] == "mcp" else "-"
            status = "[green]up[/green]" if h["reachable"] else "[red]down[/red]"
            table.add_row(h["id"], h["kind"], h["endpoint"], h["transport"], lat, tools, status)
        self.console.print(table)

    def do_services(self, arg: str) -> None:
        """services — discovered tools across the target (nmap-services style)."""
        tools = self.session.artifacts.get("tools", [])
        if not tools:
            self.console.print("[dim]no services yet — run 'scan' first[/dim]")
            return
        table = Table(title="Discovered services (tools)")
        table.add_column("Server", style="green")
        table.add_column("Tool", style="bold cyan")
        table.add_column("Sensitive")
        table.add_column("Description")
        for t in tools:
            table.add_row(
                t["server"],
                t["name"],
                "[red]yes[/red]" if t.get("sensitive") else "no",
                t.get("description", ""),
            )
        self.console.print(table)

    def do_info(self, arg: str) -> None:
        """info [module_id] — show module metadata and options."""
        module_id = arg.strip() or self.current
        if not module_id:
            self._err("no module selected (use <id>) and none given")
            return
        try:
            spec = ModuleSpec.from_module(get_module(module_id))
        except CutoutError as exc:
            self._err(str(exc))
            return
        self.console.print(
            Panel(
                f"[bold]{spec.name}[/bold]\n"
                f"tactic  : [magenta]{spec.tactic}[/magenta]\n"
                f"targets : [green]{', '.join(spec.targets) or '-'}[/green]",
                title=spec.id,
                expand=False,
            )
        )
        self._render_options(spec)

    # ---- options / datastore ----------------------------------------------
    def _render_options(self, spec: ModuleSpec) -> None:
        table = Table(title="Options")
        table.add_column("Name", style="bold cyan")
        table.add_column("Current", style="yellow")
        table.add_column("Required")
        table.add_column("Help")
        for name, opt in spec.options.items():
            current = self.opts.get(name, opt.default)
            table.add_row(
                name,
                "-" if current is None else str(current),
                "yes" if opt.required else "no",
                opt.help,
            )
        # The global datastore item (msfconsole's RHOSTS analogue).
        table.add_row(
            "TARGET", self.session.target.uri or "(in-process range)", "no", "range endpoint"
        )
        self.console.print(table)

    def do_show(self, arg: str) -> None:
        """show options|info — show the current module's options or info."""
        what = arg.strip().lower() or "options"
        if not self.current:
            self._err("no module selected; use <id> first")
            return
        spec = ModuleSpec.from_module(get_module(self.current))
        if what.startswith("opt"):
            self._render_options(spec)
        else:
            self.do_info("")

    def do_set(self, arg: str) -> None:
        """set <KEY> <VALUE> — set a module option, or TARGET for the range endpoint."""
        parts = arg.split(maxsplit=1)
        if len(parts) != 2:
            self._err("usage: set <KEY> <VALUE>")
            return
        key, value = parts[0], parts[1].strip()
        if key.upper() == "TARGET":
            self.session.target = TargetDescriptor(
                kind="range",
                name="cutout-range",
                uri=value,
                metadata={"range_id": self._range_id},
            )
            self.console.print(f"[dim]TARGET =>[/dim] {value}")
            return
        if not self.current:
            self._err("no module selected; use <id> first")
            return
        spec = ModuleSpec.from_module(get_module(self.current))
        if key not in spec.options:
            self._err(f"unknown option '{key}' (see 'show options')")
            return
        self.opts[key] = value
        self.console.print(f"[dim]{key} =>[/dim] {value}")

    def do_unset(self, arg: str) -> None:
        """unset <KEY> — clear a set option (revert to default)."""
        key = arg.strip()
        if key.upper() == "TARGET":
            self.session.target = TargetDescriptor(
                kind="range", name="cutout-range", metadata={"range_id": self._range_id}
            )
        else:
            self.opts.pop(key, None)

    # ---- execution ---------------------------------------------------------
    def do_check(self, arg: str) -> None:
        """check — run the current module's read-only susceptibility probe."""
        if not self.current:
            self._err("no module selected; use <id> first")
            return
        try:
            result = asyncio.run(self.engine.check(self.current, self.opts))
        except (CutoutError, OptionError) as exc:
            self._err(str(exc))
            return
        color = "green" if result.susceptible else "yellow"
        self.console.print(f"[{color}]susceptible={result.susceptible}[/{color}] — {result.reason}")

    def do_run(self, arg: str) -> None:
        """run — execute the current module against the session."""
        if not self.current:
            self._err("no module selected; use <id> first")
            return
        before = len(self.transcript.events)
        try:
            result = asyncio.run(self.engine.run(self.current, self.opts))
        except (CutoutError, OptionError) as exc:
            self._err(str(exc))
            return
        color = {"success": "green", "failed": "red", "skipped": "yellow"}.get(
            result.status, "white"
        )
        for event in self.transcript.events[before:]:
            self.console.print(
                f"  [dim]{event.phase.value}[/dim] [bold]{event.action}[/bold] {event.data}"
            )
        self.console.print(f"[{color}]{result.status}[/{color}] — {result.summary}")

    def do_exploit(self, arg: str) -> None:
        """exploit — alias for run."""
        self.do_run(arg)

    # ---- session state -----------------------------------------------------
    def do_sessions(self, arg: str) -> None:
        """sessions — show the chain of module results in this session."""
        table = Table(title=f"Session {self.session.id[:8]} — module chain")
        table.add_column("#", justify="right", style="dim")
        table.add_column("Module", style="bold cyan")
        table.add_column("Status")
        table.add_column("Summary")
        for i, res in enumerate(self.session.results, start=1):
            color = {"success": "green", "failed": "red", "skipped": "yellow"}.get(
                res.status, "white"
            )
            table.add_row(str(i), res.module_id, f"[{color}]{res.status}[/{color}]", res.summary)
        self.console.print(table)

    def do_loot(self, arg: str) -> None:
        """loot — show harvested secrets and key artifacts."""
        if self.session.secrets:
            table = Table(title="Loot — harvested secrets")
            table.add_column("Key", style="bold cyan")
            table.add_column("Value", style="red")
            for k, v in self.session.secrets.items():
                table.add_row(k, v)
            self.console.print(table)
        else:
            self.console.print("[dim]no secrets harvested yet[/dim]")
        artifacts = sorted(self.session.artifacts)
        if artifacts:
            self.console.print(f"[dim]artifacts:[/dim] {', '.join(artifacts)}")

    def do_graph(self, arg: str) -> None:
        """graph — show the discovered topology (nodes/edges)."""
        g = self.session.graph
        self.console.print(
            f"[bold]topology[/bold]: {g.number_of_nodes()} nodes, {g.number_of_edges()} edges"
        )
        for u, v, data in g.edges(data=True):
            self.console.print(f"  {u} [dim]--{data.get('kind', 'edge')}-->[/dim] {v}")

    def do_replay(self, arg: str) -> None:
        """replay — re-render every evidence event recorded this session."""
        table = Table(title="Evidence — this session")
        table.add_column("#", justify="right", style="dim")
        table.add_column("Module", style="bold cyan")
        table.add_column("Phase", style="magenta")
        table.add_column("Action", style="bold")
        table.add_column("Data", style="green")
        for i, e in enumerate(self.transcript.events, start=1):
            table.add_row(str(i), e.module_id, e.phase.value, e.action, str(e.data))
        self.console.print(table)
        self.console.print(f"[dim]transcript: {self.transcript.path}[/dim]")

    def do_save(self, arg: str) -> None:
        """save <path> — serialize the current session to JSON."""
        path = Path(arg.strip() or "runs/session.json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.session.model_dump_json(indent=2), encoding="utf-8")
        self.console.print(f"[dim]session saved to[/dim] {path}")

    def do_banner(self, arg: str) -> None:
        """banner — print the banner."""
        self.console.print(BANNER)

    # ---- exit --------------------------------------------------------------
    def do_exit(self, arg: str) -> bool:
        """exit — leave the console."""
        self.transcript.close()
        self.console.print("[dim]bye.[/dim]")
        return True

    def do_quit(self, arg: str) -> bool:
        """quit — leave the console."""
        return self.do_exit(arg)

    def do_EOF(self, arg: str) -> bool:
        self.console.print("")
        return self.do_exit(arg)


def run_console() -> None:
    console = CutoutConsole()
    console.console.print(BANNER)
    try:
        console.cmdloop()
    except KeyboardInterrupt:
        console.transcript.close()
        console.console.print("\n[dim]interrupted.[/dim]")
