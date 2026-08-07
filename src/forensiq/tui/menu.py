# FILE: src/forensiq/tui/menu.py
"""Interactive TUI console menu for ForensIQ.

Provides an interactive terminal-based menu powered by questionary and Rich.
Allows users to perform all major operations without memorizing CLI flags.

Usage (programmatic):
    from forensiq.tui.menu import run_menu
    run_menu()

Or via CLI:
    forensiq menu
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

if TYPE_CHECKING:
    from forensiq.pipeline.analysis_pipeline import PipelineResult

console = Console()
err_console = Console(stderr=True)

# ── Color palette mirrors the HTML report theme ───────────────────────────────
_C = {
    "critical": "bold red",
    "high": "bold yellow",
    "medium": "yellow",
    "low": "green",
    "accent": "bold cyan",
    "muted": "dim",
    "ok": "bold green",
}

_BANNER = """
[bold cyan]  ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗[/bold cyan]
[bold cyan]  ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔═══██╗[/bold cyan]
[bold cyan]  █████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║   ██║[/bold cyan]
[bold cyan]  ██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║▄▄ ██║[/bold cyan]
[bold cyan]  ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╔╝[/bold cyan]
[bold cyan]  ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚══▀▀═╝[/bold cyan]
[dim]  Memory Forensics & Threat Hunting Platform[/dim]
"""

# ── Main menu choices ────────────────────────────────────────────────────────
_MAIN_MENU_CHOICES = [
    ("[1] Analyze memory dump         — Full pipeline on a .raw/.vmem/.dmp file", "analyze"),
    ("[2] Live memory analysis         — Acquire and analyze this running Linux system", "live"),
    ("[3] Compare two memory dumps     — Detect new/changed/disappeared processes", "diff"),
    ("[4] View analysis history        — Browse past analyses stored in the local DB", "history"),
    ("[5] System requirements check    — Verify Volatility 3, ML model, Ollama, YARA", "check"),
    ("[6] Version information          — Show installed component versions", "version"),
    ("[7] Exit", "exit"),
]


def _print_banner() -> None:
    console.print(_BANNER)


def _separator() -> None:
    console.print(Rule(style="dim cyan"))


def _ask_choice(message: str, choices: list[tuple[str, str]]) -> str:
    """Display a questionary select menu and return the chosen value.

    Returns "exit" when the user cancels (Ctrl+C) or stdin is closed (EOF),
    so callers can always continue the main loop without a crash.
    """
    import questionary

    labels = [label for label, _ in choices]
    value_map = dict(choices)
    try:
        selected = questionary.select(
            message,
            choices=labels,
            style=_qs_style(),
        ).ask()
    except (KeyboardInterrupt, EOFError):
        return "exit"
    if selected is None:
        return "exit"
    return value_map.get(selected, "exit")


def _ask_path(message: str, must_exist: bool = False) -> Path | None:
    """Prompt for a file/directory path. Returns None on cancel/EOF."""
    import questionary

    while True:
        try:
            raw = questionary.path(message, style=_qs_style()).ask()
        except (KeyboardInterrupt, EOFError):
            return None
        if raw is None:
            return None
        p = Path(raw).expanduser().resolve()
        if must_exist and not p.exists():
            err_console.print(f"[red]Error:[/red] Path does not exist: {p}")
            try:
                retry = questionary.confirm("Try again?", style=_qs_style()).ask()
            except (KeyboardInterrupt, EOFError):
                return None
            if not retry:
                return None
            continue
        return p


def _ask_text(message: str, default: str = "") -> str | None:
    """Prompt for a text string. Returns None on cancel/EOF."""
    import questionary

    try:
        result = questionary.text(message, default=default, style=_qs_style()).ask()
    except (KeyboardInterrupt, EOFError):
        return None
    return str(result) if result is not None else None


def _ask_confirm(message: str, default: bool = True) -> bool:
    """Prompt for yes/no confirmation.

    On EOF the prompt cannot be answered — fall back to the provided default
    instead of crashing. Ctrl+C raises KeyboardInterrupt and is left for the
    caller to handle (it aborts the current sub-menu).
    """
    import questionary

    try:
        result = questionary.confirm(message, default=default, style=_qs_style()).ask()
    except EOFError:
        return default
    return bool(result) if result is not None else default


def _ask_output_dir(message: str, default: str = "./reports") -> Path:
    """Prompt for an output directory and return it as a resolved Path.

    Falls back to ``default`` when the user leaves the prompt empty or cancels.
    """
    raw = _ask_text(message, default=default)
    return Path(raw).expanduser().resolve() if raw else Path(default)


def _print_cached_analysis_info(cached: dict[str, Any]) -> None:
    """Display a summary of a previously cached analysis to the user."""
    ts = cached.get("analysis_ts", "unknown")
    malicious = cached.get("malicious_count", 0)
    suspicious = cached.get("suspicious_count", 0)
    total = cached.get("total_processes", 0)
    sha = (cached.get("dump_sha256") or "")[:16]

    threat_color = "red" if malicious else ("yellow" if suspicious else "green")
    threat_label = "MALICIOUS" if malicious else ("SUSPICIOUS" if suspicious else "CLEAN")

    console.print()
    console.print(
        Panel(
            f"[bold yellow]Previously analyzed dump found[/bold yellow]\n\n"
            f"[dim]SHA-256:[/dim]     [cyan]{sha}...[/cyan]\n"
            f"[dim]Analyzed on:[/dim] [white]{ts}[/white]\n"
            f"[dim]Processes:[/dim]   {total}\n"
            f"[dim]Malicious:[/dim]   {malicious}\n"
            f"[dim]Suspicious:[/dim]  {suspicious}\n\n"
            f"[{threat_color}]Threat level: {threat_label}[/{threat_color}]",
            border_style="yellow",
        )
    )
    console.print()


def _qs_style() -> Any:
    """questionary custom style matching ForensIQ dark theme."""
    from questionary import Style

    return Style(
        [
            ("qmark", "fg:cyan bold"),
            ("question", "bold"),
            ("answer", "fg:cyan bold"),
            ("pointer", "fg:cyan bold"),
            ("highlighted", "fg:cyan bold"),
            ("selected", "fg:cyan"),
            ("separator", "fg:gray"),
            ("instruction", "fg:gray"),
        ]
    )


# ── Sub-menus ────────────────────────────────────────────────────────────────


def _menu_analyze() -> None:
    """Interactive wizard for forensiq analyze."""
    console.print(
        Panel(
            "[bold]Analyze Memory Dump[/bold]\n"
            "[dim]Runs the full 7-stage pipeline: extraction → ML classification → SHAP\n"
            "explanation → YARA scanning → detector plugins → MITRE ATT&CK mapping\n"
            "→ HTML/JSON/STIX report.[/dim]",
            border_style="cyan",
            padding=(0, 1),
        )
    )
    console.print()

    # Step 1 — Input file
    console.print("[bold]Step 1 of 5 — Input file[/bold]")
    console.print(
        "[dim]Supported formats: .raw  .vmem  .dmp  .mem  (Windows dumps only for ML)[/dim]"
    )
    dump_path = _ask_path("Path to memory dump file:", must_exist=True)
    if dump_path is None:
        return

    # Step 2 — Output directory
    console.print()
    console.print("[bold]Step 2 of 5 — Output directory[/bold]")
    console.print("[dim]HTML report, JSON report, and YARA rules will be written here.[/dim]")
    output_dir = _ask_output_dir(
        "Output directory for reports:",
        default=str(Path("./reports").resolve()),
    )

    # Step 3 — Threat threshold
    console.print()
    console.print("[bold]Step 3 of 5 — Threat score threshold[/bold]")
    console.print(
        "[dim]Processes with an XGBoost score above this value are classified as malicious.\n"
        "Recommended: 0.65 (default). Lower = more detections, higher = fewer false\n"
        "positives.[/dim]"
    )
    threshold_raw = _ask_text("Threshold (0.01-0.99, Enter to use default):", default="")
    threshold: float | None = None
    if threshold_raw:
        try:
            threshold = float(threshold_raw)
            if not (0.01 <= threshold <= 0.99):
                raise ValueError
        except ValueError:
            console.print("[yellow]Invalid value — using environment default.[/yellow]")
            threshold = None

    # Step 4 — YARA generation
    console.print()
    console.print("[bold]Step 4 of 5 — YARA rule generation[/bold]")
    console.print(
        "[dim]Ollama (local LLM) generates YARA detection rules for malicious\n"
        "processes. Skip if Ollama is not running.[/dim]"
    )
    no_yara = not _ask_confirm("Generate YARA rules via Ollama?", default=True)

    # Step 5 — Advanced options
    console.print()
    console.print("[bold]Step 5 of 5 — Advanced options[/bold]")
    force = _ask_confirm(
        "Force re-analysis even if this dump was analyzed before? (ignores cached result)",
        default=False,
    )

    stix_export = _ask_confirm(
        "Export results as a STIX 2.1 threat intelligence bundle? (requires stix2 library)",
        default=False,
    )
    stix_dir: Path | None = None
    if stix_export:
        stix_raw = _ask_text("STIX output directory:", default=str(output_dir))
        stix_dir = Path(stix_raw).expanduser().resolve() if stix_raw else output_dir

    _separator()
    console.print("[bold cyan]Starting analysis pipeline...[/bold cyan]")
    console.print(f"  [dim]Dump     :[/dim] {dump_path}")
    console.print(f"  [dim]Output   :[/dim] {output_dir}")
    console.print(
        f"  [dim]Threshold:[/dim] {threshold if threshold is not None else 'default (env)'}"
    )
    console.print(f"  [dim]YARA     :[/dim] {'disabled' if no_yara else 'enabled (Ollama)'}")
    if force:
        console.print("  [dim]Force    :[/dim] re-analysis enabled")
    if stix_dir:
        console.print(f"  [dim]STIX     :[/dim] {stix_dir}")
    console.print()

    # Build and run the analysis pipeline with live progress display
    result = _run_pipeline_with_progress(
        dump_path=dump_path,
        output_dir=output_dir,
        threshold=threshold,
        generate_yara=not no_yara,
        force_reanalyze=force,
    )

    if result is None or result.report is None:
        return

    report = result.report
    _separator()
    _print_report_summary(report)

    if stix_dir is not None:
        try:
            from forensiq.reporting.stix_exporter import STIXExporter

            stix_path = STIXExporter().export(report, output_dir=stix_dir)
            console.print(f"[dim]STIX bundle:[/dim] [cyan]{stix_path}[/cyan]")
        except Exception as exc:
            err_console.print(f"[yellow]STIX export failed:[/yellow] {exc}")


def _run_pipeline_with_progress(
    dump_path: Path,
    output_dir: Path,
    *,
    threshold: float | None = None,
    generate_yara: bool = True,
    force_reanalyze: bool = False,
) -> PipelineResult | None:
    """Run the analysis pipeline and show a clean live progress table.

    Silences structured log output (level WARNING) and replaces it with
    a 5-row progress table that updates in real time as each stage
    completes.  Uses transient=True so only one final table is printed,
    avoiding repeated-frame scrollback artefacts.

    Returns the PipelineResult, or None if a fatal error occurred.
    """
    import asyncio
    import contextlib
    import logging
    import os

    from rich.live import Live
    from rich.table import Table

    from forensiq.pipeline.analysis_pipeline import AnalysisPipeline
    from forensiq.utils.logger import configure_logging

    # configure_logging() has a one-shot guard — it may already be set to INFO
    # from a previous step.  Override the stdlib root logger level directly so
    # the structured log lines are suppressed for the duration of the pipeline.
    configure_logging(log_level="WARNING", log_format="console")
    _root_logger = logging.getLogger()
    _prev_level = _root_logger.level
    _root_logger.setLevel(logging.WARNING)

    # ── Stage registry ────────────────────────────────────────────────────────
    stages = [
        ("extraction", "Extracting artifacts via Volatility 3"),
        ("classification", "Classifying processes with ML model"),
        ("detectors", "Running detector plugins (MITRE mapping)"),
        ("yara", "Generating YARA detection rules via Ollama"),
        ("report", "Building HTML / JSON / STIX reports"),
    ]
    stage_status: dict[str, str] = {k: "pending" for k, _ in stages}
    stage_detail: dict[str, str] = {}

    status_label = {
        "pending": "[dim]waiting[/dim]",
        "running": "[cyan]running[/cyan]",
        "done": "[green]done   [/green]",
        "skip": "[dim]skipped[/dim]",
        "failed": "[red]failed [/red]",
    }

    def _render() -> Table:
        t = Table(
            show_header=False,
            box=None,
            padding=(0, 2),
            expand=False,
            show_edge=False,
        )
        t.add_column("N", style="dim", width=3, no_wrap=True)
        t.add_column("Stage", width=46, no_wrap=True)
        t.add_column("Status", width=10, no_wrap=True)
        t.add_column("Detail", style="dim", width=52, no_wrap=True)
        for i, (key, label) in enumerate(stages, 1):
            st = stage_status[key]
            label_str = f"[bold]{label}[/bold]" if st == "running" else label
            t.add_row(str(i), label_str, status_label.get(st, ""), stage_detail.get(key, ""))
        return t

    def _on_stage(stage: str, data: Any) -> None:
        if stage == "classification":
            vectors = data
            mal = sum(1 for v in vectors if getattr(v, "is_malicious", False))
            sus = sum(
                1
                for v in vectors
                if not getattr(v, "is_malicious", False) and getattr(v, "threat_score", 0) >= 0.35
            )
            total = len(vectors)
            stage_detail["classification"] = (
                f"{total} processes  |  {mal} malicious  |  {sus} suspicious"
            )
        elif stage == "detectors":
            findings = data
            crit = sum(1 for f in findings if getattr(f, "severity", "") in ("critical", "high"))
            stage_detail["detectors"] = f"{len(findings)} findings  |  {crit} critical/high"
        elif stage == "yara":
            rules = data
            valid = sum(1 for r in rules if getattr(r, "is_valid", False))
            stage_detail["yara"] = f"{valid}/{len(rules)} rules valid"
        elif stage == "mitre":
            techniques = data
            cnt = len(techniques)
            if cnt:
                existing = stage_detail.get("detectors", "")
                stage_detail["detectors"] = (
                    f"{existing}  |  {cnt} MITRE techniques"
                    if existing
                    else f"{cnt} MITRE techniques"
                )

    # When the pipeline finds a prior analysis of the same dump SHA-256, show
    # the cached summary and ask whether to re-run from scratch. Accepting the
    # cached result returns a PipelineResult with no report object — the caller
    # must recognise that as a success, not a failure.
    def _on_cached_result(cached: dict[str, Any]) -> bool:
        _print_cached_analysis_info(cached)
        if force_reanalyze:
            console.print("[yellow]Force re-analysis enabled — proceeding.[/yellow]")
            return True
        return _ask_confirm(
            "This dump has been analyzed before. Run a full re-analysis?",
            default=False,
        )

    # Mirrors the stage table as the pipeline progresses.  `live` is bound
    # later inside the Live context below; as a free variable it resolves at
    # call time, which is always after the context is entered.
    def _callback(stage: str, data: object) -> None:
        _on_stage(stage, data)
        if stage == "classification":
            stage_status["extraction"] = "done"
            stage_status["classification"] = "done"
            stage_status["detectors"] = "running"
        elif stage == "detectors":
            stage_status["detectors"] = "done"
            stage_status["yara" if generate_yara else "report"] = "running"
        elif stage == "yara":
            stage_status["yara"] = "done"
            stage_status["report"] = "running"
        live.update(_render())

    pipeline = AnalysisPipeline(
        show_progress=False,
        generate_yara=generate_yara,
        generate_html=True,
        generate_json=True,
        force_reanalyze=force_reanalyze,
        on_cached_result=_on_cached_result,
        on_stage_complete=_callback,
    )

    console.print("[bold]Analysis pipeline[/bold]")
    console.print("[dim]Processing the memory dump through 5 stages.[/dim]")
    console.print()

    stage_status["extraction"] = "running"
    result = None

    # Open /dev/null once via a context manager — no fd leak possible.
    # redirect_stderr routes structlog's PrintLoggerFactory output away from
    # the terminal while Live is rendering.  The root logger level (set above)
    # silences the stdlib backend; redirect_stderr catches any direct writes.
    # Both are restored automatically when the `with` block exits, even on
    # exceptions — no manual try/finally needed.
    with open(os.devnull, "w") as _devnull, contextlib.redirect_stderr(_devnull):  # noqa: PTH123
        try:
            with Live(_render(), console=console, refresh_per_second=4, transient=True) as live:

                result = asyncio.run(
                    pipeline.run(
                        dump_path=dump_path,
                        output_dir=output_dir,
                        threshold=threshold,
                    )
                )

                if result.report is not None:
                    for k in stage_status:
                        if stage_status[k] in ("pending", "running"):
                            stage_status[k] = "done"
                    if not generate_yara:
                        stage_status["yara"] = "skip"
                        stage_detail["yara"] = "disabled (--no-yara)"
                elif result.exit_code in (0, 1):
                    # Cached result accepted (no report object, valid exit code)
                    # — reflect that in the table instead of leaving the
                    # extraction stage hanging as "running".
                    for k in stage_status:
                        stage_status[k] = "done"
                    stage_detail["extraction"] = "cached result accepted"
                    stage_status["yara"] = "skip"
                    stage_detail["yara"] = "not re-run (cached)"
                    stage_status["report"] = "done"
                else:
                    # Genuine failure (exit_code 2/3) — do not pretend it was a
                    # cached hit; mark the failed stage so the table is honest.
                    for k in stage_status:
                        if stage_status[k] == "running":
                            stage_status[k] = "failed"
                    if result.error:
                        stage_detail["extraction"] = result.error[:60]
                live.update(_render())
        finally:
            # Restore the root log level regardless of pipeline outcome.
            # stderr is restored automatically by redirect_stderr on exit.
            _root_logger.setLevel(_prev_level)

    # Live erased itself — print the final state once, cleanly
    console.print(_render())
    console.print()

    if result is None:
        console.print("[red]Analysis failed — no report generated.[/red]")
        return None

    if result.report is None and result.exit_code in (0, 1):
        # Cached result accepted: the pipeline returned early with no report
        # object but a valid exit code — treat it as a successful (reused) run.
        console.print("[green]Using previously cached analysis result.[/green]")
        return result

    if result.report is None:
        console.print("[red]Analysis failed — no report generated.[/red]")
        return None
    return result


def _menu_diff() -> None:
    """Interactive wizard for forensiq diff."""
    console.print(
        Panel(
            "[bold]Compare Memory Dumps[/bold]\n"
            "[dim]Takes a BEFORE snapshot and an AFTER snapshot of the same system and reports\n"
            "which processes appeared, disappeared, or changed between the two captures.\n"
            "Useful for detecting process injection or malware that runs only temporarily.[/dim]",
            border_style="cyan",
            padding=(0, 1),
        )
    )
    console.print()

    before = _ask_path("Path to BEFORE dump:", must_exist=True)
    if before is None:
        return

    after = _ask_path("Path to AFTER dump:", must_exist=True)
    if after is None:
        return

    output_dir = _ask_output_dir("Output directory:", default="./reports")

    _separator()
    console.print("[bold cyan]Comparing dumps…[/bold cyan]")
    console.print(f"  [dim]Before:[/dim] {before}")
    console.print(f"  [dim]After:[/dim]  {after}")
    console.print()

    import asyncio

    from forensiq.pipeline.diff_pipeline import DiffPipeline
    from forensiq.utils.logger import configure_logging

    configure_logging(log_level="INFO", log_format="console")
    diff_pipeline = DiffPipeline()
    diff_result = asyncio.run(diff_pipeline.run(before, after, output_dir))

    _separator()
    table = Table(title="Diff Summary", box=box.ROUNDED, border_style="cyan", show_header=True)
    table.add_column("Category")
    table.add_column("Count", justify="right")
    table.add_row("[green]New processes[/green]", str(len(diff_result.new_processes)))
    table.add_row("[red]Disappeared processes[/red]", str(len(diff_result.disappeared_processes)))
    table.add_row("[yellow]Changed processes[/yellow]", str(len(diff_result.changed_processes)))
    table.add_row("[dim]Before SHA-256[/dim]", diff_result.before_sha256[:16] + "…")
    table.add_row("[dim]After SHA-256[/dim]", diff_result.after_sha256[:16] + "…")
    console.print(table)

    if diff_result.new_processes:
        console.print(
            "\n[green]New PIDs:[/green] "
            f"{', '.join(str(p) for p in diff_result.new_processes[:10])}"
            + (" …" if len(diff_result.new_processes) > 10 else "")
        )
    if diff_result.disappeared_processes:
        console.print(
            "[red]Gone PIDs:[/red] "
            f"{', '.join(str(p) for p in diff_result.disappeared_processes[:10])}"
            + (" …" if len(diff_result.disappeared_processes) > 10 else "")
        )


def _menu_history() -> None:
    """Show analysis history from the SQLite database."""
    console.print(
        Panel(
            "[bold]Analysis History[/bold]\n"
            "[dim]Lists the 20 most recent analyses stored in the local ForensIQ\n"
            "database (~/.forensiq/forensiq.db).\n"
            "Each row shows when the dump was analyzed, its threat level, and a\n"
            "SHA-256 fingerprint.[/dim]",
            border_style="cyan",
            padding=(0, 1),
        )
    )

    import asyncio

    async def _fetch() -> list[dict[str, Any]]:
        from forensiq.db.manager import ForensiqDatabase

        async with ForensiqDatabase() as db:
            return await db.get_recent_analyses(limit=20)

    try:
        analyses = asyncio.run(_fetch())
    except Exception as exc:
        err_console.print(f"[red]Database error:[/red] {exc}")
        return

    if not analyses:
        console.print("[dim]No analyses in history yet.[/dim]")
        return

    table = Table(box=box.ROUNDED, border_style="dim", show_header=True, padding=(0, 1))
    table.add_column("#", style="dim", justify="right")
    table.add_column("Date")
    table.add_column("Dump")
    table.add_column("Threat", justify="center")
    table.add_column("Malicious", justify="right")
    table.add_column("SHA-256")

    for i, row in enumerate(analyses, 1):
        threat_level = row.get("threat_level", "unknown")
        # threat_level not stored in DB — derive from malicious_count
        raw_mal = row.get("malicious_count")
        mal = int(raw_mal) if raw_mal is not None else 0
        if mal > 5:
            threat_level = "critical"
        elif mal > 0:
            threat_level = "high"
        else:
            threat_level = "low"
        color = _C.get(threat_level, "white")
        table.add_row(
            str(i),
            str(row.get("analysis_ts", ""))[:19],
            str(row.get("dump_name", ""))[:30],
            f"[{color}]{threat_level.upper()}[/{color}]",
            str(row.get("malicious_count", 0)),
            str(row.get("dump_sha256", ""))[:16] + "…",
        )

    console.print(table)


def _menu_check() -> None:
    """Run system requirements check."""
    console.print(
        Panel(
            "[bold]System Requirements Check[/bold]\n"
            "[dim]Verifies that all tools and libraries ForensIQ depends on are\n"
            "installed and reachable.\n"
            "Missing optional components reduce functionality but do not prevent\n"
            "basic analysis.[/dim]",
            border_style="cyan",
            padding=(0, 1),
        )
    )
    checks = [
        ("Python version", sys.version.split()[0], ">=3.12"),
        ("volatility3", _which_version("vol"), "required"),
        ("yara-python", _import_version("yara"), "optional"),
        ("xgboost", _import_version("xgboost"), "required"),
        ("stix2", _import_version("stix2"), "optional"),
        ("questionary", _import_version("questionary"), "required"),
        ("aiosqlite", _import_version("aiosqlite"), "required"),
    ]
    table = Table(box=box.SIMPLE, show_header=True, padding=(0, 1))
    table.add_column("Component")
    table.add_column("Version / Path")
    table.add_column("Status", justify="center")
    table.add_column("Role", style="dim")
    role_map = {
        "Python version": "runtime",
        "volatility3": "required \u2014 memory extraction",
        "yara-python": "optional \u2014 in-memory YARA scanning",
        "xgboost": "required \u2014 ML threat classification",
        "stix2": "optional \u2014 STIX 2.1 threat intel export",
        "questionary": "required \u2014 interactive TUI menu",
        "aiosqlite": "required \u2014 analysis history database",
    }
    for name, ver, req in checks:
        if ver:
            status = "[green]OK[/green]"
        elif req == "optional":
            status = "[yellow]not installed[/yellow]"
        else:
            status = "[red]MISSING[/red]"
        table.add_row(name, ver or "not found", status, role_map.get(name, ""))
    console.print(table)


def _which_version(cmd: str) -> str:
    import shutil
    import subprocess

    if not shutil.which(cmd):
        return ""
    try:
        r = subprocess.run([cmd, "--version"], capture_output=True, text=True, timeout=5)
        return (r.stdout or r.stderr or "").strip().split("\n")[0][:40]
    except Exception:
        return "found"


def _import_version(module: str) -> str:
    try:
        import importlib.metadata

        return importlib.metadata.version(module)
    except Exception:
        try:
            __import__(module)
            return "installed"
        except ImportError:
            return ""


def _menu_version() -> None:
    """Show version information."""
    try:
        import importlib.metadata

        ver = importlib.metadata.version("forensiq")
    except Exception:
        ver = "dev"
    console.print(
        Panel(
            f"[bold cyan]ForensIQ[/bold cyan]  v{ver}\n"
            f"[dim]Python:[/dim] {sys.version.split()[0]}\n"
            f"[dim]STIX 2.1:[/dim] {_import_version('stix2') or 'not installed'}\n"
            f"[dim]XGBoost:[/dim] {_import_version('xgboost') or 'not installed'}",
            title="Version",
            border_style="cyan",
            padding=(0, 1),
        )
    )


def _print_report_summary(report) -> None:  # type: ignore[no-untyped-def]
    """Print a concise Rich summary of a completed ForensiqReport."""
    threat_color = _C.get(report.threat_level, "white")
    console.print(
        Panel(
            f"[bold]Threat Level:[/bold] [{threat_color}]{report.threat_level.upper()}"
            f"[/{threat_color}]\n"
            f"Total processes: {report.total_processes}  |  "
            f"[red]Malicious: {report.malicious_count}[/red]  |  "
            f"[yellow]Suspicious: {report.suspicious_count}[/yellow]",
            title="[bold green]Analysis Complete[/bold green]",
            border_style="green",
            padding=(0, 1),
        )
    )

    if report.top_threats:
        table = Table(title="Top Threats", box=box.SIMPLE, show_header=True, padding=(0, 1))
        table.add_column("PID", justify="right", style="cyan")
        table.add_column("Process")
        table.add_column("Score", justify="right")
        table.add_column("Ensemble", justify="right")
        for vec in report.top_threats[:5]:
            table.add_row(
                str(vec.pid),
                vec.name or "?",
                f"{vec.threat_score:.3f}",
                f"{vec.ensemble_score:.3f}",
            )
        console.print(table)


# ── Main entry point ─────────────────────────────────────────────────────────


def run_menu() -> None:
    """Launch the interactive TUI main menu loop."""
    _print_banner()
    console.print(
        "[dim]  Use the arrow keys to navigate, Enter to select, Ctrl+C to return\n"
        "to this menu.[/dim]"
    )
    _separator()

    dispatch = {
        "analyze": _menu_analyze,
        "live": _menu_live,
        "diff": _menu_diff,
        "history": _menu_history,
        "check": _menu_check,
        "version": _menu_version,
    }

    while True:
        console.print()
        choice = _ask_choice("Select an option:", _MAIN_MENU_CHOICES)

        if choice == "exit":
            console.print("\n[dim]Session ended.[/dim]\n")
            break

        action = dispatch.get(choice)
        if action:
            console.print()
            try:
                action()
            except KeyboardInterrupt:
                console.print("\n[dim]Cancelled. Returning to main menu.[/dim]")
            except Exception as exc:
                err_console.print(f"\n[red]Error:[/red] {exc}")
        else:
            console.print(f"[yellow]Unknown action:[/yellow] {choice}")


# Imported last to avoid a circular import: menu_live reuses helpers from this
# module (console, prompts, _run_pipeline_with_progress), so it must be loaded
# after those names exist.
from forensiq.tui.menu_live import _menu_live  # noqa: E402  (bottom import)
