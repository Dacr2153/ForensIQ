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

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

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
    """Display a questionary select menu and return the chosen value."""
    import questionary

    labels = [label for label, _ in choices]
    value_map = dict(choices)
    selected = questionary.select(
        message,
        choices=labels,
        style=_qs_style(),
    ).ask()
    if selected is None:
        return "exit"
    return value_map.get(selected, "exit")


def _ask_path(message: str, must_exist: bool = False) -> Path | None:
    """Prompt for a file/directory path."""
    import questionary

    while True:
        raw = questionary.path(message, style=_qs_style()).ask()
        if raw is None:
            return None
        p = Path(raw).expanduser().resolve()
        if must_exist and not p.exists():
            err_console.print(f"[red]Error:[/red] Path does not exist: {p}")
            retry = questionary.confirm("Try again?", style=_qs_style()).ask()
            if not retry:
                return None
            continue
        return p


def _ask_text(message: str, default: str = "") -> str | None:
    """Prompt for a text string."""
    import questionary

    result = questionary.text(message, default=default, style=_qs_style()).ask()
    return result


def _ask_confirm(message: str, default: bool = True) -> bool:
    """Prompt for yes/no confirmation."""
    import questionary

    result = questionary.confirm(message, default=default, style=_qs_style()).ask()
    return bool(result)


def _qs_style():
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
            "[dim]Runs the full 7-stage pipeline: extraction → ML classification → SHAP explanation\n"
            "→ YARA scanning → detector plugins → MITRE ATT&CK mapping → HTML/JSON/STIX report.[/dim]",
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
    output_dir_raw = _ask_text(
        "Output directory for reports:",
        default=str(Path("./reports").resolve()),
    )
    output_dir = (
        Path(output_dir_raw).expanduser().resolve() if output_dir_raw else Path("./reports")
    )

    # Step 3 — Threat threshold
    console.print()
    console.print("[bold]Step 3 of 5 — Threat score threshold[/bold]")
    console.print(
        "[dim]Processes with an XGBoost score above this value are classified as malicious.\n"
        "Recommended: 0.65 (default). Lower = more detections, higher = fewer false positives.[/dim]"
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
        "[dim]Ollama (local LLM) generates YARA detection rules for malicious processes.\nSkip if Ollama is not running.[/dim]"
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


def _menu_live() -> None:
    """Interactive wizard for live memory analysis via /proc/kcore or LiME."""
    from forensiq.acquisition.live_memory import (
        LiveMemoryError,
        acquire_lime_dump,
        check_live_requirements,
    )

    console.print(
        Panel(
            "[bold]Live Memory Analysis[/bold]\n"
            "[dim]Checks system prerequisites then acquires and analyzes the running Linux kernel memory.\n"
            "Two acquisition methods are supported:\n"
            "  /proc/kcore  \u2014 standard kernels (fastest, no module needed)\n"
            "  LiME         \u2014 linux-hardened kernels where /proc/kcore is disabled[/dim]",
            border_style="cyan",
            padding=(0, 1),
        )
    )
    console.print()

    reqs = check_live_requirements()

    # ── Diagnostics table ────────────────────────────────────────────────────
    console.print("[dim]Prerequisite check:[/dim]")
    table = Table(show_header=True, box=box.SIMPLE, padding=(0, 1))
    table.add_column("Requirement", style="dim")
    table.add_column("Status")
    table.add_column("Notes", style="dim")

    table.add_row(
        "Linux OS",
        "[green]OK[/green]" if reqs["is_linux"] else "[red]FAIL[/red]",
        "",
    )
    table.add_row(
        "Kernel variant",
        "[yellow]hardened[/yellow]" if reqs.get("kernel_hardened") else "[green]standard[/green]",
        reqs.get("kernel_release", ""),
    )
    table.add_row(
        "Running as root",
        "[green]OK[/green]" if reqs["has_root"] else "[yellow]NO[/yellow]",
        "sudo required for both acquisition methods" if not reqs["has_root"] else "",
    )
    table.add_row(
        "/proc/kcore",
        "[green]available[/green]" if reqs["kcore_exists"] else "[red]disabled[/red]",
        "CONFIG_PROC_KCORE=n on hardened kernel"
        if reqs.get("kernel_hardened") and not reqs["kcore_exists"]
        else "",
    )
    table.add_row(
        "LiME module (lime.ko)",
        "[green]found[/green]" if reqs.get("lime_available") else "[yellow]not found[/yellow]",
        reqs.get("lime_module_path")
        or (
            "Can build automatically: sudo forensiq live --build-lime"
            if reqs.get("lime_can_build")
            else "lime.ko not found \u2014 must build from source"
        ),
    )
    table.add_row(
        "Kernel ISF (Volatility 3)",
        "[green]built[/green]" if reqs.get("linux_isf_available") else "[yellow]not built[/yellow]",
        reqs.get("linux_isf_path")
        or (
            "Build: forensiq live --build-isf"
            if reqs.get("linux_isf_can_build")
            else "Symbol table required for Volatility 3 Linux plugins"
        ),
    )
    console.print(table)
    console.print()

    # ── Route to the available acquisition method ─────────────────────────────
    if reqs["ready"]:
        # /proc/kcore is accessible — use it directly
        _run_live_kcore(reqs)
        return

    # /proc/kcore not available — check LiME
    if not reqs["is_linux"]:
        console.print("[red]Live analysis requires Linux.[/red]")
        return

    if reqs.get("kernel_hardened") and not reqs["kcore_exists"]:
        console.print(
            "[yellow]Note:[/yellow] This linux-hardened kernel has /proc/kcore disabled (security policy).\n"
            "[dim]ForensIQ will use LiME (Linux Memory Extractor) instead.[/dim]\n"
        )

    if not reqs.get("lime_available"):
        # Neither method available — show install instructions with build option
        if reqs.get("lime_can_build"):
            console.print(
                "\n[yellow]LiME not built yet[/yellow] — but all build tools are available.\n"
            )
            if not _ask_confirm(
                "Build LiME from source now? (requires internet + ~30s)", default=True
            ):
                console.print(
                    "[dim]Manual build:[/dim]\n"
                    "  git clone https://github.com/504ensicsLabs/LiME\n"
                    "  make -C LiME/src\n"
                    "  sudo forensiq live --lime --lime-module LiME/src/lime.ko"
                )
                return

            if not reqs["has_root"]:
                console.print(
                    "[red]Root is required for LiME acquisition after build.[/red]\n"
                    "Re-run: [cyan]sudo forensiq menu[/cyan]"
                )
                return

            from forensiq.acquisition.live_memory import LiveMemoryError, build_lime_from_source

            try:
                built_path = build_lime_from_source(
                    progress_callback=lambda msg: console.print(f"  [dim]{msg}[/dim]")
                )
            except (RuntimeError, LiveMemoryError) as exc:
                err_console.print(f"[red]Build failed:[/red] {exc}")
                return

            console.print(f"\n[green]LiME built:[/green] {built_path}\n")
            # Re-check now that module is built
            from forensiq.acquisition.live_memory import check_live_requirements

            reqs = check_live_requirements()
        else:
            console.print(
                Panel(
                    "[bold yellow]LiME not found — missing build tools[/bold yellow]\n\n"
                    "Install build prerequisites:\n"
                    "  [cyan]sudo pacman -S git base-devel linux-hardened-headers[/cyan]\n\n"
                    "Then build LiME:\n"
                    "  [dim]git clone https://github.com/504ensicsLabs/LiME\n"
                    "  make -C LiME/src[/dim]\n\n"
                    "Or let ForensIQ build it automatically:\n"
                    "  [cyan]sudo forensiq live --build-lime[/cyan]",
                    border_style="yellow",
                    padding=(0, 2),
                )
            )
            return

    # LiME is available — offer acquisition
    console.print(f"[dim]Acquisition module:[/dim] [cyan]{reqs['lime_module_path']}[/cyan]\n")

    # ── ISF check (Volatility 3 Linux symbol table) ───────────────────────────
    if not reqs.get("linux_isf_available"):
        if reqs.get("linux_isf_can_build"):
            console.print(
                "[yellow]Kernel ISF not built yet[/yellow] — Volatility 3 needs it to analyze the LiME dump.\n"
                "[dim]Uses BTF (/sys/kernel/btf/vmlinux) + System.map. Takes ~60s.[/dim]\n"
            )
            if _ask_confirm("Build kernel ISF (symbol table) now?", default=True):
                from forensiq.acquisition.linux_isf import build_linux_isf

                try:
                    isf_path = build_linux_isf(
                        progress_cb=lambda msg: console.print(f"  [dim]{msg}[/dim]")
                    )
                    console.print(f"\n[green]ISF built:[/green] {isf_path}\n")
                    reqs["linux_isf_available"] = True
                    reqs["linux_isf_path"] = str(isf_path)
                except (RuntimeError, Exception) as exc:
                    err_console.print(f"[red]ISF build failed:[/red] {exc}")
                    console.print(
                        "[yellow]Analysis will proceed but Volatility 3 plugins may fail.[/yellow]\n"
                        "[dim]Run manually: sudo forensiq live --build-isf[/dim]"
                    )
        else:
            console.print(
                "[yellow]Kernel ISF not available.[/yellow] Volatility 3 Linux analysis may fail.\n"
                "[dim]Build requires: BTF (/sys/kernel/btf/vmlinux) + System.map + Go + dwarf2json[/dim]"
            )

    if not reqs["has_root"]:
        console.print(
            "[red]Root privileges required for LiME.[/red]\n"
            "Re-launch with: [cyan]sudo forensiq menu[/cyan]"
        )
        return

    console.print(
        Panel(
            "[bold yellow]Security notice[/bold yellow]\n\n"
            "LiME will read ALL physical memory from the running kernel and write it to disk.\n"
            "The resulting file contains sensitive data: credentials, encryption keys, process\n"
            "memory, and kernel internals. Treat the dump file as a high-confidentiality artifact.\n\n"
            "[dim]Ensure the output directory is not world-readable and is stored securely.[/dim]",
            border_style="yellow",
            padding=(0, 1),
        )
    )
    if not _ask_confirm(
        "Proceed with live memory acquisition?",
        default=False,
    ):
        return

    output_dir_raw = _ask_text("Output directory for reports:", default="./reports")
    output_dir = (
        Path(output_dir_raw).expanduser().resolve() if output_dir_raw else Path("./reports")
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    lime_dump_path = output_dir / "live_memory.lime"

    no_yara = not _ask_confirm("Generate YARA rules via Ollama?", default=False)

    _separator()
    console.print("[bold cyan]Acquiring live memory via LiME[/bold cyan]")
    console.print(f"  [dim]Output:[/dim] {lime_dump_path}")
    console.print("  [dim]RAM   :[/dim] this may take several minutes depending on total memory")
    console.print()

    from forensiq.acquisition.live_memory import find_lime_module

    lime_module_path = find_lime_module()
    if lime_module_path is None:
        err_console.print("[red]LiME module disappeared — cannot proceed.[/red]")
        return

    try:
        dump_path = acquire_lime_dump(
            output_path=lime_dump_path,
            lime_module=lime_module_path,
        )
    except (LiveMemoryError, PermissionError) as exc:
        err_console.print(f"\n[red]LiME acquisition failed:[/red] {exc}")
        return

    size_mb = dump_path.stat().st_size / 1_048_576
    console.print(f"[green]Memory dump acquired[/green]  {size_mb:.0f} MB  ->  {dump_path}")
    console.print()

    _run_live_pipeline(dump_path, output_dir, no_yara=no_yara)


def _run_live_kcore(reqs: dict) -> None:
    """Run live analysis using /proc/kcore (called when kcore is ready)."""
    console.print(
        Panel(
            "[bold yellow]Security notice[/bold yellow]\n\n"
            "/proc/kcore exposes all physical memory of the running kernel as an ELF core file.\n"
            "The analysis report will contain sensitive kernel and process data.\n\n"
            "[dim]Ensure the output directory is not world-readable and is stored securely.[/dim]",
            border_style="yellow",
            padding=(0, 1),
        )
    )
    if not _ask_confirm(
        "Proceed with live analysis via /proc/kcore?",
        default=False,
    ):
        return

    output_dir_raw = _ask_text("Output directory for reports:", default="./reports")
    output_dir = (
        Path(output_dir_raw).expanduser().resolve() if output_dir_raw else Path("./reports")
    )
    no_yara = not _ask_confirm("Generate YARA rules via Ollama?", default=False)

    from forensiq.acquisition.live_memory import LiveMemoryError, get_kcore_path

    try:
        dump_path = get_kcore_path()
    except LiveMemoryError as exc:
        err_console.print(f"[red]Failed to access /proc/kcore:[/red] {exc}")
        return

    _separator()
    console.print("[bold cyan]Starting live analysis via /proc/kcore[/bold cyan]\n")
    result = _run_pipeline_with_progress(
        dump_path=dump_path,
        output_dir=output_dir,
        threshold=None,
        generate_yara=not no_yara,
        force_reanalyze=True,
    )
    if result is not None and result.report is not None:
        _separator()
        _print_report_summary(result.report)


def _run_pipeline_with_progress(
    dump_path: Path,
    output_dir: Path,
    *,
    threshold: float | None = None,
    generate_yara: bool = True,
    force_reanalyze: bool = False,
):
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
    _STAGES = [
        ("extraction", "Extracting artifacts via Volatility 3"),
        ("classification", "Classifying processes with ML model"),
        ("detectors", "Running detector plugins (MITRE mapping)"),
        ("yara", "Generating YARA detection rules via Ollama"),
        ("report", "Building HTML / JSON / STIX reports"),
    ]
    stage_status: dict[str, str] = {k: "pending" for k, _ in _STAGES}
    stage_detail: dict[str, str] = {}

    _STATUS_LABEL = {
        "pending": "[dim]waiting[/dim]",
        "running": "[cyan]running[/cyan]",
        "done": "[green]done   [/green]",
        "skip": "[dim]skipped[/dim]",
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
        for i, (key, label) in enumerate(_STAGES, 1):
            st = stage_status[key]
            label_str = f"[bold]{label}[/bold]" if st == "running" else label
            t.add_row(str(i), label_str, _STATUS_LABEL.get(st, ""), stage_detail.get(key, ""))
        return t

    def _on_stage(stage: str, data: object) -> None:
        if stage == "classification":
            vectors = data  # type: ignore[assignment]
            mal = sum(1 for v in vectors if getattr(v, "is_malicious", False))  # type: ignore[union-attr]
            sus = sum(
                1
                for v in vectors
                if not getattr(v, "is_malicious", False) and getattr(v, "threat_score", 0) >= 0.35
            )  # type: ignore[union-attr]
            total = len(vectors)  # type: ignore[arg-type]
            stage_detail["classification"] = (
                f"{total} processes  |  {mal} malicious  |  {sus} suspicious"
            )
        elif stage == "detectors":
            findings = data  # type: ignore[assignment]
            crit = sum(1 for f in findings if getattr(f, "severity", "") in ("critical", "high"))  # type: ignore[union-attr]
            stage_detail["detectors"] = f"{len(findings)} findings  |  {crit} critical/high"  # type: ignore[arg-type]
        elif stage == "yara":
            rules = data  # type: ignore[assignment]
            valid = sum(1 for r in rules if getattr(r, "is_valid", False))  # type: ignore[union-attr]
            stage_detail["yara"] = f"{valid}/{len(rules)} rules valid"  # type: ignore[arg-type]
        elif stage == "mitre":
            techniques = data  # type: ignore[assignment]
            cnt = len(techniques)  # type: ignore[arg-type]
            if cnt:
                existing = stage_detail.get("detectors", "")
                stage_detail["detectors"] = (
                    f"{existing}  |  {cnt} MITRE techniques"
                    if existing
                    else f"{cnt} MITRE techniques"
                )

    pipeline = AnalysisPipeline(
        show_progress=False,
        generate_yara=generate_yara,
        generate_html=True,
        generate_json=True,
        force_reanalyze=force_reanalyze,
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

                pipeline._on_stage_complete = _callback

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
                    stage_status["report"] = "done"
                live.update(_render())
        finally:
            # Restore the root log level regardless of pipeline outcome.
            # stderr is restored automatically by redirect_stderr on exit.
            _root_logger.setLevel(_prev_level)

    # Live erased itself — print the final state once, cleanly
    console.print(_render())
    console.print()

    if result is None or result.report is None:
        console.print("[red]Analysis failed — no report generated.[/red]")
        return None
    return result


def _run_live_pipeline(dump_path: Path, output_dir: Path, *, no_yara: bool) -> None:
    """Wrapper kept for LiME acquisition path."""
    result = _run_pipeline_with_progress(
        dump_path=dump_path,
        output_dir=output_dir,
        threshold=None,
        generate_yara=not no_yara,
        force_reanalyze=True,
    )
    if result is not None and result.report is not None:
        _separator()
        _print_report_summary(result.report)


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

    output_dir_raw = _ask_text("Output directory:", default="./reports")
    output_dir = (
        Path(output_dir_raw).expanduser().resolve() if output_dir_raw else Path("./reports")
    )

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
            f"\n[green]New PIDs:[/green] {', '.join(str(p) for p in diff_result.new_processes[:10])}"
            + (" …" if len(diff_result.new_processes) > 10 else "")
        )
    if diff_result.disappeared_processes:
        console.print(
            f"[red]Gone PIDs:[/red] {', '.join(str(p) for p in diff_result.disappeared_processes[:10])}"
            + (" …" if len(diff_result.disappeared_processes) > 10 else "")
        )


def _menu_history() -> None:
    """Show analysis history from the SQLite database."""
    console.print(
        Panel(
            "[bold]Analysis History[/bold]\n"
            "[dim]Lists the 20 most recent analyses stored in the local ForensIQ database (~/.forensiq/forensiq.db).\n"
            "Each row shows when the dump was analyzed, its threat level, and a SHA-256 fingerprint.[/dim]",
            border_style="cyan",
            padding=(0, 1),
        )
    )

    import asyncio

    async def _fetch():
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
        mal = int(row.get("malicious_count", 0))
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
            "[dim]Verifies that all tools and libraries ForensIQ depends on are installed and reachable.\n"
            "Missing optional components reduce functionality but do not prevent basic analysis.[/dim]",
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
            f"[bold]Threat Level:[/bold] [{threat_color}]{report.threat_level.upper()}[/{threat_color}]\n"
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
        "[dim]  Use the arrow keys to navigate, Enter to select, Ctrl+C to return to this menu.[/dim]"
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
