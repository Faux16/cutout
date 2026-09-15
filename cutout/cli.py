"""Cutout command-line interface (Typer + Rich).

Commands:
    list                     list all registered modules
    info <id>                show one module's metadata and options
    run <id> [--opt k=v]...   run a module and write a JSONL transcript
    hunt <mcp-target>        recon + frisk a real MCP server and draft findings
    replay <transcript>      re-render a past run's evidence events
    catalog [path]           show catalog coverage (implemented vs planned)
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC, datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cutout.engine import (
    Engine,
    EvidenceWriter,
    ModuleResult,
    ModuleSpec,
    OptionError,
    Session,
    TargetDescriptor,
    get_module,
    get_registry,
    load_catalog,
    read_events,
)
from cutout.engine.errors import CutoutError

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Cutout — authorized security testing of agentic systems.",
)
console = Console()
err_console = Console(stderr=True)


def _parse_opts(pairs: list[str]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for pair in pairs:
        if "=" not in pair:
            raise typer.BadParameter(f"expected key=value, got '{pair}'")
        key, value = pair.split("=", 1)
        parsed[key.strip()] = value
    return parsed


def _resolve(query: str) -> str:
    """Resolve a module reference to an ID: exact ID, exact alias, or unique substring."""
    registry = get_registry()
    if query in registry:
        return query
    low = query.lower()
    by_id = {mid.lower(): mid for mid in registry}
    if low in by_id:
        return by_id[low]
    by_alias = {registry[m].alias.lower(): m for m in registry if registry[m].alias}
    if low in by_alias:
        return by_alias[low]
    matches = [
        m
        for m in sorted(registry)
        if low in f"{m} {registry[m].alias} {registry[m].name} {registry[m].tactic}".lower()
    ]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise typer.BadParameter(f"no module matches '{query}' (try 'cutout list')")
    raise typer.BadParameter(f"'{query}' is ambiguous: {', '.join(matches)}")


@app.command("list")
def list_modules() -> None:
    """List all registered modules."""

    registry = get_registry()
    table = Table(title="Registered modules")
    table.add_column("Alias", style="bold yellow")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Tactic", style="magenta")
    table.add_column("Targets", style="green")
    for module_id in sorted(registry):
        spec = ModuleSpec.from_module(registry[module_id])
        table.add_row(spec.alias or "-", spec.id, spec.name, spec.tactic, ", ".join(spec.targets))
    console.print(table)
    console.print(f"[dim]{len(registry)} module(s) registered.[/dim]")


@app.command("info")
def info(module_id: str = typer.Argument(..., help="Technique ID, e.g. CUT-INV-001")) -> None:
    """Show one module's metadata and declared options."""

    try:
        spec = ModuleSpec.from_module(get_module(_resolve(module_id)))
    except CutoutError as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    body = (
        f"[bold]{spec.name}[/bold]\n"
        f"tactic  : [magenta]{spec.tactic}[/magenta]\n"
        f"targets : [green]{', '.join(spec.targets) or '-'}[/green]"
    )
    console.print(Panel(body, title=spec.id, expand=False))

    table = Table(title="Options")
    table.add_column("Name", style="bold cyan")
    table.add_column("Type")
    table.add_column("Required")
    table.add_column("Default")
    table.add_column("Help")
    for name, opt in spec.options.items():
        table.add_row(
            name,
            opt.type,
            "yes" if opt.required else "no",
            "-" if opt.default is None else repr(opt.default),
            opt.help,
        )
    if spec.options:
        console.print(table)
    else:
        console.print("[dim]no options[/dim]")


def _default_transcript(module_id: str) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    safe = module_id.replace("/", "_")
    return Path("runs") / f"{safe}-{stamp}.jsonl"


@app.command("run")
def run(
    module_id: str = typer.Argument(..., help="Technique ID to run, e.g. CUT-INV-001"),
    opt: list[str] = typer.Option(
        [], "--opt", "-o", help="Module option as key=value (repeatable)."
    ),
    target: str | None = typer.Option(
        None,
        "--target",
        help="Target: an http(s):// range orchestrator URL; mcp://host:port/path or "
        "'mcp+stdio:<command>' to recon a real MCP server (use with 'casing'); a state dir "
        "(persistent in-process); or omit for a fresh in-memory range.",
    ),
    out: Path | None = typer.Option(
        None, "--out", help="Transcript path (default: runs/<id>-<ts>.jsonl)."
    ),
) -> None:
    """Run a module and write its evidence transcript to JSONL."""

    module_id = _resolve(module_id)  # accept alias / substring / exact ID
    transcript = out or _default_transcript(module_id)
    try:
        options = _parse_opts(opt)
        result = asyncio.run(_run_module(module_id, options, transcript, target))
    except (CutoutError, OptionError) as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        err_console.print(f"[red]error:[/red] {type(exc).__name__}: {exc}")
        if target:
            err_console.print(f"[dim]could not reach target {target}; is it up?[/dim]")
        raise typer.Exit(code=1) from exc

    color = {"success": "green", "failed": "red", "skipped": "yellow"}.get(result.status, "white")
    console.print(
        Panel(
            f"status : [{color}]{result.status}[/{color}]\n"
            f"summary: {result.summary}\n"
            f"data   : {result.data}",
            title=f"{module_id} result",
            expand=False,
        )
    )
    console.print(f"[dim]transcript written to[/dim] {transcript}")


async def _run_module(
    module_id: str, options: dict[str, str], transcript: Path, target: str | None
) -> ModuleResult:
    session = Session(target=TargetDescriptor(uri=target)) if target else Session()
    async with EvidenceWriter(transcript) as writer:
        engine = Engine(session=session, writer=writer)
        return await engine.run(module_id, options)


@app.command("hunt")
def hunt(
    target: str = typer.Argument(
        ...,
        help="MCP target to hunt: 'mcp+stdio:<command>' (stdio server) or "
        "mcp://host:port/mcp (HTTP). Only test servers you are authorized to.",
    ),
    out: Path | None = typer.Option(
        None, "--out", help="Transcript path (default: runs/hunt-<ts>.jsonl)."
    ),
) -> None:
    """Recon + frisk a real MCP server and draft findings (the OSS-hunt workflow).

    Enumerates the server's tools, safely probes them for reachable resources (local file
    read, SSRF, command exec), and drafts a finding for each confirmed capability. Probes
    are benign; you still confirm exploitability, check prior art, and disclose responsibly.
    """
    transcript = out or _default_transcript("hunt")
    try:
        session = asyncio.run(_hunt(target, transcript))
    except (CutoutError, OptionError) as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        err_console.print(f"[red]error:[/red] {type(exc).__name__}: {exc}")
        err_console.print(f"[dim]could not reach or drive target {target}; is it up?[/dim]")
        raise typer.Exit(code=1) from exc

    _render_hunt(target, session, transcript)


async def _hunt(target: str, transcript: Path) -> Session:
    session = Session(target=TargetDescriptor(uri=target))
    async with EvidenceWriter(transcript) as writer:
        engine = Engine(session=session, writer=writer)
        await engine.run("CUT-RECON-001")  # casing — enumerate tools/hosts
        await engine.run("CUT-DISC-004")  # frisk — probe reachable resources
    return session


def _render_hunt(target: str, session: Session, transcript: Path) -> None:
    hosts = session.artifacts.get("hosts", [])
    tools = session.artifacts.get("tools", [])
    findings = session.artifacts.get("resource_findings", [])

    server = hosts[0]["endpoint"] if hosts else target
    sensitive = sum(1 for t in tools if t.get("sensitive"))
    console.print(
        Panel(
            f"target : [cyan]{target}[/cyan]\n"
            f"server : {server}\n"
            f"tools  : {len(tools)} ({sensitive} sensitive)\n"
            f"findings: [{'red' if findings else 'green'}]{len(findings)}[/]",
            title="hunt summary",
            expand=False,
        )
    )

    if not findings:
        console.print(
            "[green]no reachable-resource findings — target defended these probes.[/green]"
        )
        console.print(f"[dim]transcript written to[/dim] {transcript}")
        return

    table = Table(title="Confirmed capabilities (verify before reporting)")
    table.add_column("Tool", style="bold cyan")
    table.add_column("Capability")
    table.add_column("Severity")
    table.add_column("Vector", style="green")
    for f in findings:
        sev = f["severity"]
        color = {"critical": "red", "high": "red", "medium": "yellow"}.get(sev, "white")
        table.add_row(f["tool"], f["capability"], f"[{color}]{sev}[/{color}]", f["vector"])
    console.print(table)

    for f in findings:
        sev = f["severity"]
        color = {"critical": "red", "high": "red", "medium": "yellow"}.get(sev, "white")
        console.print(
            Panel(
                f"[bold]{f['tool']} — {f['capability']}[/bold] ([{color}]{sev}[/{color}])\n"
                f"• Vector: {f['vector']}\n"
                f"• Detail: {f['detail']}\n"
                "• Confirm: reproduce end-to-end against a value you control (a marker file / "
                "your own endpoint), not real data.\n"
                "• Prior art: search advisories/CVEs/issues for this package before reporting.\n"
                "• Disclose: coordinated disclosure only; see ETHICS.md.",
                title="finding draft",
                expand=False,
            )
        )
    console.print(f"[dim]transcript written to[/dim] {transcript}")


@app.command("replay")
def replay(
    transcript: Path = typer.Argument(..., help="Path to a JSONL transcript."),
) -> None:
    """Re-render a past run's evidence events."""

    if not transcript.exists():
        err_console.print(f"[red]error:[/red] no such transcript: {transcript}")
        raise typer.Exit(code=1)

    events = read_events(transcript)
    table = Table(title=f"Replay — {transcript}")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Timestamp", style="dim")
    table.add_column("Module", style="bold cyan")
    table.add_column("Phase", style="magenta")
    table.add_column("Action", style="bold")
    table.add_column("Data", style="green")
    for i, event in enumerate(events, start=1):
        table.add_row(
            str(i),
            event.ts.isoformat(),
            event.module_id,
            event.phase.value,
            event.action,
            str(event.data),
        )
    console.print(table)
    console.print(f"[dim]{len(events)} event(s).[/dim]")


@app.command("catalog")
def catalog(
    path: Path | None = typer.Argument(
        None, help="Catalog YAML path (default: repo catalog.yaml)."
    ),
) -> None:
    """Show which catalog techniques have a registered module."""

    try:
        entries = load_catalog(path)
    except (OSError, CutoutError) as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    table = Table(title="Technique catalog coverage")
    table.add_column("ID", style="bold cyan")
    table.add_column("Name")
    table.add_column("Tactic", style="magenta")
    table.add_column("Status")
    implemented = 0
    for entry in entries:
        if entry.implemented:
            implemented += 1
            status = "[green]implemented[/green]"
        else:
            status = "[yellow]planned[/yellow]"
        table.add_row(entry.id, entry.name, entry.tactic, status)
    console.print(table)
    console.print(f"[dim]{implemented}/{len(entries)} implemented.[/dim]")


@app.command("canary")
def canary_cmd(
    port: int = typer.Option(8700, "--port", help="Port to serve on."),
    host: str = typer.Option("0.0.0.0", "--host", help="Bind address."),
    content: str | None = typer.Option(
        None, "--content", help="Content the lookup/fetch tools return (plant test content)."
    ),
    log: Path = typer.Option(Path("runs/canary.jsonl"), "--log", help="JSONL log path."),
) -> None:
    """Run the canary connector — a logging MCP endpoint for authorized agent observation."""
    try:
        import uvicorn
        from cutout_range.service.canary import canary_server, http_app
    except ImportError as exc:
        err_console.print("[red]error:[/red] needs the range extra: pip install 'cutout[range]'")
        raise typer.Exit(code=1) from exc

    if content is not None:
        os.environ["CUTOUT_CANARY_CONTENT"] = content
    os.environ["CUTOUT_CANARY_LOG"] = str(log)
    console.print(
        f"[bold]canary connector[/bold] on http://{host}:{port}/mcp  (log: {log})\n"
        "[dim]wire this into an agent you are authorized to test; Ctrl-C to stop.[/dim]"
    )
    uvicorn.run(http_app(canary_server()), host=host, port=port, log_level="warning")


@app.command("canary-report")
def canary_report(
    log: Path = typer.Argument(..., help="Canary JSONL log to summarize."),
) -> None:
    """Summarize a canary log and draft a finding skeleton (exfil candidates highlighted)."""
    if not log.exists():
        err_console.print(f"[red]error:[/red] no such log: {log}")
        raise typer.Exit(code=1)
    events = [json.loads(line) for line in log.read_text().splitlines() if line.strip()]
    exfil = [e for e in events if e.get("exfil_candidate")]

    table = Table(title=f"Canary log — {log}")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Timestamp", style="dim")
    table.add_column("Tool", style="bold cyan")
    table.add_column("Arguments", style="green")
    table.add_column("Flag")
    for i, e in enumerate(events, start=1):
        flag = "[red]EXFIL?[/red]" if e.get("exfil_candidate") else ""
        table.add_row(str(i), e.get("ts", ""), e.get("tool", ""), str(e.get("arguments", {})), flag)
    console.print(table)
    console.print(f"[dim]{len(events)} call(s), {len(exfil)} exfil candidate(s).[/dim]")

    if exfil:
        console.print(
            Panel(
                "[bold]Finding draft[/bold] (reconcile with the program brief):\n"
                "• Summary: agent was steered to send data to an attacker-controlled tool.\n"
                f"• Evidence: {len(exfil)} call(s) to a sink/URL carrying data (see EXFIL? rows).\n"
                "• Material harm: <what an attacker gains — leaked data / unauthorized action>.\n"
                "• Repro: <the benign task + planted content that caused it>.\n"
                "• Mitigation: enforce a data/instruction trust boundary; gate tools on intent.",
                title="report skeleton",
                expand=False,
            )
        )


@app.command("console")
def console_cmd() -> None:
    """Launch the interactive msfconsole-style shell (persistent session state)."""

    from cutout.console import run_console

    run_console()


def main() -> None:
    app()


if __name__ == "__main__":
    main()
