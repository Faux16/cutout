"""Cutout command-line interface (Typer + Rich).

Commands:
    list                     list all registered modules
    info <id>                show one module's metadata and options
    run <id> [--opt k=v]...   run a module and write a JSONL transcript
    replay <transcript>      re-render a past run's evidence events
    catalog [path]           show catalog coverage (implemented vs planned)
"""

from __future__ import annotations

import asyncio
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
        help="Target range: an http(s):// orchestrator URL (running stack), a state dir "
        "(persistent in-process), or omit for a fresh in-memory range.",
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


@app.command("console")
def console_cmd() -> None:
    """Launch the interactive msfconsole-style shell (persistent session state)."""

    from cutout.console import run_console

    run_console()


def main() -> None:
    app()


if __name__ == "__main__":
    main()
