# FILE: src/forensiq/cli.py
"""ForensIQ command-line interface.

Provides the `forensiq` command with the following sub-commands:

    forensiq analyze   — Analyze a Windows memory dump end-to-end
    forensiq train     — Train the XGBoost model on CIC-MalMem2022 dataset
    forensiq check     — Check system requirements and tool availability
    forensiq live      — Analyze live Linux memory via /proc/kcore
    forensiq diff      — Compare two memory dumps
    forensiq menu      — Launch the interactive TUI console menu
    forensiq version   — Print version information

Exit codes:
    0 — Analysis complete, no threats found (or other success)
    1 — Analysis complete, threats detected (malicious processes found)
    2 — Analysis failed due to a critical error
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from forensiq.utils.logger import configure_logging, get_logger

app = typer.Typer(
    name="forensiq",
    help="[bold cyan]ForensIQ[/bold cyan] — Memory Forensics & Threat Hunting Platform",
    rich_markup_mode="rich",
    no_args_is_help=True,
    add_completion=False,
)
console = Console(stderr=False)
err_console = Console(stderr=True)


# ══════════════════════════════════════════════════════════════════════════════
# forensiq analyze
# ══════════════════════════════════════════════════════════════════════════════


@app.command("analyze")
def analyze(
    dump: Path = typer.Option(
        ...,
        "--dump",
        "-d",
        help="Path to the Windows memory dump file (raw, vmem, dmp).",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        resolve_path=True,
    ),
    output: Path = typer.Option(
        Path("./reports"),
        "--output",
        "-o",
        help="Directory for output reports and YARA rules.",
        writable=True,
        resolve_path=True,
    ),
    threshold: float = typer.Option(
        None,  # type: ignore[assignment]
        "--threshold",
        "-t",
        help="Threat score threshold for 'malicious' classification (0.0-1.0). "
        "Overrides FORENSIQ_THREAT_THRESHOLD env var.",
        min=0.01,
        max=0.99,
    ),
    no_yara: bool = typer.Option(
        False,
        "--no-yara",
        help="Skip YARA rule generation (useful when Ollama is not running).",
    ),
    no_html: bool = typer.Option(
        False,
        "--no-html",
        help="Skip HTML report generation.",
    ),
    stream: bool = typer.Option(
        False,
        "--stream",
        help="Stream incremental results to stdout as each analysis phase completes "
        "(classification, detectors, MITRE mapping). Useful for long-running analyses.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Force re-analysis even if this dump was previously analyzed (skip cache).",
    ),
    output_stix: Path | None = typer.Option(
        None,
        "--output-stix",
        help="Export analysis as STIX 2.1 bundle to this directory (optional).",
    ),
    log_level: str = typer.Option(
        "INFO",
        "--log-level",
        "-l",
        help="Log level: DEBUG, INFO, WARNING, ERROR.",
    ),
    log_format: str = typer.Option(
        "console",
        "--log-format",
        help="Log format: 'console' (human-readable) or 'json' (structured).",
    ),
) -> None:
    """[bold]Analyze a Windows memory dump for fileless malware and threats.[/bold]

    Runs the full analysis pipeline:
      1. Extracts artifacts via Volatility 3 (pslist, netscan, dlllist, malfind, vadinfo)
      2. Computes 20 per-process ML features (v2)
      3. Classifies with XGBoost + IsolationForest ensemble
      4. Generates SHAP explanations for suspicious processes
      5. Scans injected memory with built-in YARA rules
      6. Creates YARA detection rules via Ollama (optional, auto-detects model)
      7. Produces HTML, JSON, and STIX 2.1 forensic reports

    [yellow]Requirements:[/yellow]
      - Volatility 3 installed and 'vol' in PATH
      - XGBoost model trained (run: [cyan]forensiq train[/cyan])
      - Ollama running with any model installed (for AI YARA; use [cyan]--no-yara[/cyan] to skip)
    """
    configure_logging(log_level=log_level.upper(), log_format=log_format)
    log = get_logger("forensiq.cli.analyze")

    # ── Print banner ──────────────────────────────────────────────────────────
    console.print(
        Panel(
            "[bold cyan]ForensIQ[/bold cyan] — Memory Forensics & Threat Hunting Platform\n\n"
            f"[dim]Dump   :[/dim] [cyan]{dump}[/cyan]\n"
            f"[dim]Output :[/dim] [cyan]{output}[/cyan]\n\n"
            "[dim]Pipeline stages: extraction \u2192 feature engineering \u2192 ML"
            " classification \u2192 SHAP explanation \u2192 detector plugins \u2192 MITRE"
            " ATT&CK mapping \u2192 report generation[/dim]",
            border_style="cyan",
            padding=(0, 1),
        )
    )

    # ── Validate dump file ────────────────────────────────────────────────────
    if not dump.exists():
        err_console.print(f"[red]Error:[/red] Dump file not found: {dump}")
        raise typer.Exit(code=2)

    if dump.stat().st_size < 1024:
        err_console.print(f"[red]Error:[/red] Dump file too small (< 1 KB): {dump}")
        raise typer.Exit(code=2)

    # ── Run async pipeline ────────────────────────────────────────────────────
    from forensiq.pipeline.analysis_pipeline import AnalysisPipeline

    # ── Streaming callback ────────────────────────────────────────────────────
    stream_callback = _make_stream_callback(console) if stream else None

    # ── Cached-result callback ─────────────────────────────────────────────────
    # Called when a previous analysis of the same dump SHA-256 is found.
    # Returns True to proceed with full re-analysis, False to use cached result.
    is_tty = sys.stdin.isatty()

    def _on_cached_result(cached: dict) -> bool:
        """Show cached analysis summary and ask user whether to re-analyze."""
        _print_cached_analysis_info(cached, console)
        if force:
            console.print("[yellow]--force specified: proceeding with full re-analysis.[/yellow]")
            return True
        if not is_tty:
            # Non-interactive: accept cached result silently
            console.print("[dim]Non-interactive mode: using cached result.[/dim]")
            return False
        try:
            reanalyze = typer.confirm(
                "\nThis dump has been analyzed before. Run a full re-analysis?",
                default=False,
            )
            return reanalyze
        except Exception:
            return False

    pipeline = AnalysisPipeline(
        show_progress=True,
        generate_yara=not no_yara,
        generate_html=not no_html,
        generate_json=True,
        on_stage_complete=stream_callback,
        force_reanalyze=force,
        on_cached_result=_on_cached_result,
    )

    try:
        result = asyncio.run(
            pipeline.run(
                dump_path=dump,
                output_dir=output,
                threshold=threshold,
            )
        )
    except KeyboardInterrupt:
        err_console.print("\n[yellow]Analysis interrupted by user.[/yellow]")
        raise typer.Exit(code=2) from None
    except Exception as exc:
        err_console.print(f"[red]Fatal error:[/red] {exc}")
        log.exception("Unexpected pipeline error")
        raise typer.Exit(code=2) from exc

    # ── Handle error result ───────────────────────────────────────────────────
    if result.exit_code == 2:
        err_console.print(f"[red]Analysis failed:[/red] {result.error}")
        _print_troubleshooting_hint()
        raise typer.Exit(code=2)

    # ── Degraded result: report produced but ML classification unavailable ───
    if result.exit_code == 3 or result.degraded_reason:
        err_console.print(
            "[yellow]Warning:[/yellow] Analysis completed but ML classification"
            " was NOT applied — results are degraded.[/yellow]"
        )
        err_console.print(f"[yellow]          {result.degraded_reason}[/yellow]")
        err_console.print(
            "[yellow]          Do not treat this as a clean result. "
            "See 'forensiq train --help' to build a model.[/yellow]"
        )

    # ── Cached result: no report object ──────────────────────────────────────
    if result.report is None and result.exit_code in (0, 1):
        # Pipeline returned early with cached result — already printed info
        raise typer.Exit(code=result.exit_code)

    # ── Print summary ──────────────────────────────────────────────────────────
    report = result.report
    if report is None:
        err_console.print("[red]Error:[/red] No report generated.")
        raise typer.Exit(code=2)

    _print_summary(report, result)

    # ── Optional STIX 2.1 export ──────────────────────────────────────────────
    if output_stix is not None:
        try:
            from forensiq.reporting.stix_exporter import STIXExporter

            stix_path = STIXExporter().export(report, output_dir=output_stix)
            console.print(f"[dim]STIX 2.1 bundle:[/dim] [cyan]{stix_path}[/cyan]")
        except ImportError:
            err_console.print(
                "[yellow]Warning:[/yellow] stix2 library not installed. "
                "Install with: pip install stix2"
            )
        except Exception as exc:
            err_console.print(f"[yellow]Warning:[/yellow] STIX export failed: {exc}")

    raise typer.Exit(code=result.exit_code)


def _print_cached_analysis_info(cached: dict, console: Console) -> None:
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
            f"[dim]Result:[/dim]      [bold {threat_color}]{threat_label}[/bold {threat_color}]\n"
            f"[dim]Processes:[/dim]   {total} total  •  "
            f"[red]{malicious} malicious[/red]  •  [yellow]{suspicious} suspicious[/yellow]",
            border_style="yellow",
            title="[yellow]Cache Hit[/yellow]",
            padding=(0, 1),
        )
    )


def _print_summary(report, result) -> None:  # type: ignore[no-untyped-def]
    """Print analysis summary to console."""
    threat_colors = {
        "critical": "red",
        "high": "orange3",
        "medium": "yellow",
        "low": "green",
    }
    threat_level = report.threat_level
    color = threat_colors.get(threat_level, "white")

    console.print()
    console.print(
        Panel(
            f"[bold {color}]Threat Level: {threat_level.upper()}[/bold {color}]\n\n"
            f"Processes Analyzed : [bold]{report.total_processes}[/bold]\n"
            f"Suspicious         : [bold yellow]{report.suspicious_count}[/bold yellow]"
            f"  [dim](score 35-65%)[/dim]\n"
            f"Malicious          : [bold {'red' if report.malicious_count else 'green'}]"
            f"{report.malicious_count}[/bold {'red' if report.malicious_count else 'green'}]"
            f"  [dim](score >65%)[/dim]\n"
            f"YARA Rules Valid   : [bold cyan]{report.valid_yara_count}[/bold cyan]\n"
            f"Timeline Events    : [bold]{len(report.timeline)}[/bold]"
            f"  [dim](MITRE ATT&CK observations)[/dim]",
            title="[bold]Analysis Complete[/bold]",
            border_style=color,
            padding=(0, 1),
        )
    )

    # Top threats table
    if report.top_threats:
        table = Table(
            title="Top Threats by Score",
            caption=(
                "Malfind = injected memory regions  |  VAD RWX = executable writable "
                "segments  |  Ext. Conns = external network connections"
            ),
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
        )
        table.add_column("PID", style="dim cyan", width=8)
        table.add_column("Process", style="bold")
        table.add_column("Score", justify="right", width=8)
        table.add_column("Malfind", justify="right", width=8)
        table.add_column("VAD RWX", justify="right", width=8)
        table.add_column("Ext. Conns", justify="right", width=10)

        for v in report.top_threats[:10]:
            score_pct = f"{v.threat_score:.1%}"
            score_color = (
                "red" if v.threat_score >= 0.75 else "yellow" if v.threat_score >= 0.5 else "white"
            )
            table.add_row(
                str(v.pid),
                v.name,
                f"[{score_color}]{score_pct}[/{score_color}]",
                f"[red]{v.malfind_hits}[/red]" if v.malfind_hits > 0 else "0",
                f"[red]{v.vad_rwx_count}[/red]" if v.vad_rwx_count > 0 else "0",
                f"[red]{v.external_connection_count}[/red]"
                if v.external_connection_count > 0
                else "0",
            )
        console.print(table)

    # Output files
    console.print()
    console.print("[dim]Generated files:[/dim]")
    if result.report_path:
        console.print(f"  HTML report : [link={result.report_path}]{result.report_path}[/link]")
    if result.json_path:
        console.print(f"  JSON report : {result.json_path}")
    if result.yara_dir:
        console.print(f"  YARA rules  : {result.yara_dir}/")
    console.print()


def _make_stream_callback(console: Console):  # type: ignore[no-untyped-def]
    """Build a streaming callback that prints incremental results as each phase completes.

    Returns a callable suitable for AnalysisPipeline(on_stage_complete=...).
    Each stage emits different data:
        "classification" → list[ProcessFeatureVector]: print suspicious/malicious processes
        "detectors"      → list[DetectorResult]: print critical/high severity findings
        "yara"           → list[YARAResult]: print count of valid rules generated
        "mitre"          → list[dict]: print detected ATT&CK techniques
    """
    from rich import box
    from rich.rule import Rule
    from rich.table import Table

    def _callback(stage: str, data: object) -> None:
        if stage == "classification":
            vectors = data  # list[ProcessFeatureVector]
            suspicious = [v for v in vectors if v.threat_score >= 0.35]  # type: ignore[union-attr]
            if not suspicious:
                return
            console.print()
            console.print(Rule("[bold yellow]Streaming — Classification Results[/bold yellow]"))
            table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold cyan")
            table.add_column("PID", width=7)
            table.add_column("Process", style="bold")
            table.add_column("Score", justify="right", width=8)
            table.add_column("Status", width=12)
            for v in sorted(suspicious, key=lambda x: -x.threat_score)[:15]:
                score_color = "red" if v.threat_score >= 0.65 else "yellow"
                status = "[red]MALICIOUS[/red]" if v.is_malicious else "[yellow]SUSPICIOUS[/yellow]"
                table.add_row(
                    str(v.pid),
                    v.name,
                    f"[{score_color}]{v.threat_score:.1%}[/{score_color}]",
                    status,
                )
            console.print(table)

        elif stage == "detectors":
            findings = data  # list[DetectorResult]
            critical_high = [
                f for f in findings if getattr(f, "severity", "") in ("critical", "high")
            ]  # type: ignore[union-attr]
            if not critical_high:
                return
            console.print()
            console.print(
                Rule("[bold red]Streaming — Detector Findings (Critical / High)[/bold red]")
            )
            for f in critical_high[:10]:
                sev = getattr(f, "severity", "?").upper()
                color = "red" if sev == "CRITICAL" else "orange3"
                pid = getattr(f, "pid", 0)
                proc = getattr(f, "process_name", "?")
                title = getattr(f, "title", "?")
                mitre = getattr(f, "mitre_technique", "")
                mitre_str = f" [{mitre}]" if mitre else ""
                console.print(
                    f"  [{color}][{sev}][/{color}] PID {pid} ({proc}): {title}{mitre_str}"
                )

        elif stage == "yara":
            rules = data  # list[YARAResult]
            valid = [r for r in rules if getattr(r, "is_valid", False)]  # type: ignore[union-attr]
            console.print()
            console.print(
                f"  [cyan]YARA:[/cyan] {len(valid)}/{len(rules)} rules generated and validated"  # type: ignore[arg-type]
            )

        elif stage == "mitre":
            techniques = data  # list[dict]
            if not techniques:
                return
            console.print()
            console.print(
                Rule("[bold blue]Streaming — MITRE ATT&CK Techniques Detected[/bold blue]")
            )
            for t in techniques[:8]:  # type: ignore[union-attr]
                tid = t.get("technique_id", "?")
                name = t.get("name", "?")
                count = t.get("observation_count", 0)
                console.print(f"  [blue]{tid}[/blue] {name} — {count} observation(s)")
            console.print()

    return _callback


def _print_troubleshooting_hint() -> None:
    """Print troubleshooting help after a failure."""
    err_console.print()
    err_console.print("[dim]Troubleshooting:[/dim]")
    err_console.print("  • Run [cyan]forensiq check[/cyan] to verify dependencies")
    err_console.print(
        "  • Ensure Volatility 3 is installed: [cyan]pip install volatility3[/cyan]"
    )
    err_console.print(
        "  • Or set the executable path: [cyan]FORENSIQ_VOLATILITY_PATH=/path/to/vol[/cyan] in .env"
    )
    err_console.print(
        "  • Train the ML model: [cyan]forensiq train --data /path/to/CIC-MalMem2022/[/cyan]"
    )
    err_console.print(
        "  • Set log level for details: [cyan]forensiq analyze --log-level DEBUG ...[/cyan]"
    )
    err_console.print()


# ══════════════════════════════════════════════════════════════════════════════
# forensiq train
# ══════════════════════════════════════════════════════════════════════════════


@app.command("train")
def train(
    data: Path = typer.Option(
        ...,
        "--data",
        help="Path to CIC-MalMem2022 dataset (CSV file or directory of CSVs).",
        exists=True,
        resolve_path=True,
    ),
    output: Path = typer.Option(
        None,  # type: ignore[assignment]
        "--output",
        help="Output directory for model file. Defaults to forensiq config path.",
        resolve_path=True,
    ),
    test_split: float = typer.Option(
        0.2,
        "--test-split",
        help="Fraction of data to use for testing (0.0-0.5).",
        min=0.05,
        max=0.5,
    ),
    seed: int = typer.Option(
        42,
        "--seed",
        help="Random seed for reproducibility.",
    ),
    log_level: str = typer.Option(
        "INFO",
        "--log-level",
        help="Log level: DEBUG, INFO, WARNING, ERROR.",
    ),
) -> None:
    """[bold]Train the XGBoost threat classification model.[/bold]

    Downloads and uses the CIC-MalMem2022 dataset (University of New Brunswick).
    Dataset URL: [link]https://www.unb.ca/cic/datasets/malmem-2022.html[/link]

    [yellow]Expected dataset structure:[/yellow]
      - Single CSV file, or directory containing CSV files
      - Must have columns: pslist.nproc, malfind.ninjections, dlllist.ndlls, Class, etc.
      - Class column values: Benign, Spyware, Ransomware, Trojan, Backdoor

    [yellow]Output:[/yellow]
      Trained model saved as [cyan]forensiq_model.joblib[/cyan] + metadata JSON.
    """
    configure_logging(log_level=log_level.upper(), log_format="console")

    from forensiq.config.settings import get_settings

    settings = get_settings()

    if output is None:
        output_path = settings.get_model_path()
    else:
        # If user gave a directory, append the default filename
        output_path = output / "forensiq_model.joblib" if output.is_dir() else output

    console.print(
        Panel(
            f"[bold cyan]ForensIQ Model Training[/bold cyan]\n\n"
            f"[dim]Dataset:[/dim] [cyan]{data}[/cyan]\n"
            f"[dim]Output:[/dim]  [cyan]{output_path}[/cyan]\n"
            f"[dim]Test split:[/dim] {test_split:.0%}",
            border_style="cyan",
            padding=(0, 1),
        )
    )

    # Import training module
    try:
        from forensiq.ml.training.train import main as train_main
    except ImportError as exc:
        err_console.print(f"[red]Error:[/red] Training dependencies not available: {exc}")
        err_console.print("Install with: [cyan]pip install forensiq[train][/cyan]")
        raise typer.Exit(code=2) from exc

    # Patch sys.argv and call training main
    import sys

    original_argv = sys.argv
    sys.argv = [
        "forensiq-train",
        "--data",
        str(data),
        "--output",
        str(output_path),
        "--test-split",
        str(test_split),
        "--seed",
        str(seed),
    ]
    try:
        train_main()
        console.print("\n[bold green]Training complete![/bold green]")
        console.print(f"Model saved to: [cyan]{output_path}[/cyan]")
    except SystemExit as exc:
        if exc.code != 0:
            err_console.print("[red]Training failed.[/red]")
            raise typer.Exit(code=2) from exc
    except Exception as exc:
        err_console.print(f"[red]Training error:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    finally:
        sys.argv = original_argv


# ══════════════════════════════════════════════════════════════════════════════
# forensiq check
# ══════════════════════════════════════════════════════════════════════════════


@app.command("check")
def check() -> None:
    """[bold]Check system requirements and tool availability.[/bold]

    Verifies:
      • Volatility 3 installation
      • ML model availability
      • Ollama server connectivity
      • yara-python library
      • Python version
    """
    configure_logging(log_level="WARNING", log_format="console")

    import subprocess
    import sys as _sys

    from forensiq.config.settings import get_settings

    settings = get_settings()

    table = Table(
        title="ForensIQ System Check",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        padding=(0, 1),
    )
    table.add_column("Component", style="bold", width=28)
    table.add_column("Status", width=10)
    table.add_column("Details")

    all_ok = True

    def add_row(name: str, ok: bool, detail: str) -> None:
        nonlocal all_ok
        if not ok:
            all_ok = False
        status = "[green]OK[/green]" if ok else "[red]FAIL[/red]"
        table.add_row(name, status, detail)

    def add_warn(name: str, detail: str) -> None:
        """Add a row that warns but does not fail the overall check."""
        table.add_row(name, "[yellow]WARN[/yellow]", detail)

    # Python version
    py_version = f"{_sys.version_info.major}.{_sys.version_info.minor}.{_sys.version_info.micro}"
    py_ok = _sys.version_info >= (3, 12)
    add_row("Python", py_ok, f"Python {py_version} {'(OK)' if py_ok else '(requires 3.12+)'}")

    # Volatility 3
    vol_path = settings.get_volatility_executable()
    try:
        proc = subprocess.run(
            [vol_path, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        vol_version = (proc.stdout or proc.stderr or "").strip().split("\n")[0]
        add_row("Volatility 3", True, vol_version or vol_path)
    except FileNotFoundError:
        add_row("Volatility 3", False, f"'{vol_path}' not found — install: pip install volatility3")
    except Exception as exc:
        add_row("Volatility 3", False, str(exc))

    # yara-python
    try:
        import yara  # type: ignore[import]

        yara.compile(source="rule test { condition: false }")
        add_row("yara-python", True, "yara module available, compile test passed")
    except ImportError:
        add_row("yara-python", False, "Not installed — install: pip install yara-python")
    except Exception as exc:
        add_row("yara-python", False, f"Compile test failed: {exc}")

    # ML Model
    model_path = settings.get_model_path()
    if settings.is_model_available():
        size_kb = round(model_path.stat().st_size / 1024, 1)
        meta_path = model_path.with_suffix(".json")
        meta_info = ""
        if meta_path.exists():
            import json

            try:
                with meta_path.open() as f:
                    meta = json.load(f)
                meta_info = f" | trained: {meta.get('trained_at', 'unknown')}"
            except Exception:  # noqa: S110
                pass  # Optional metadata — display degrades gracefully
        add_row("ML Model", True, f"{model_path} ({size_kb} KB{meta_info})")
    else:
        add_row("ML Model", False, f"Not found at {model_path} — run: forensiq train --data ...")

    # Ollama
    from forensiq.llm.ollama_client import OllamaClient

    ollama_client = OllamaClient(
        base_url=settings.OLLAMA_BASE_URL,
        model=settings.OLLAMA_MODEL,
        timeout=5,
    )
    try:
        resolved_model = asyncio.run(ollama_client.resolve_model())
    except Exception:
        resolved_model = None

    if resolved_model is None:
        add_warn(
            "Ollama + Model",
            f"Not reachable or no model installed at {settings.OLLAMA_BASE_URL} — "
            f"start the server with [cyan]ollama serve[/cyan] and install a model "
            f"([cyan]ollama pull {settings.OLLAMA_MODEL}[/cyan]). "
            f"Analysis will still produce a basic report without AI content.",
        )
    elif resolved_model == settings.OLLAMA_MODEL:
        add_row(
            "Ollama + Model",
            True,
            f"{resolved_model} available at {settings.OLLAMA_BASE_URL}",
        )
    else:
        add_row(
            "Ollama + Model",
            True,
            f"Configured {settings.OLLAMA_MODEL} not installed — using available "
            f"{resolved_model} at {settings.OLLAMA_BASE_URL}",
        )

    console.print(table)

    if all_ok:
        console.print("\n[bold green]All checks passed! ForensIQ is ready.[/bold green]")
    else:
        console.print(
            "\n[yellow]Some checks failed.[/yellow] "
            "ForensIQ may still work with limited functionality.\n"
            "  • YARA generation requires Ollama (skip with [cyan]--no-yara[/cyan])\n"
            "  • Classification requires ML model (skip shows scores=0.0)\n"
        )

    # ── Live memory check ─────────────────────────────────────────────────────
    console.print()
    from forensiq.acquisition.live_memory import check_live_requirements

    live = check_live_requirements()
    live_table = Table(
        title="Live Memory Acquisition",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        padding=(0, 1),
    )
    live_table.add_column("Check", style="bold", width=28)
    live_table.add_column("Status", width=14)
    live_table.add_column("Details")

    def _live_ok(v: bool) -> str:
        return "[green]OK[/green]" if v else "[yellow]No[/yellow]"

    live_table.add_row("Linux OS", _live_ok(bool(live["is_linux"])), "Linux kernel required")
    live_table.add_row(
        "Kernel",
        "[yellow]hardened[/yellow]" if live.get("kernel_hardened") else "[green]standard[/green]",
        live.get("kernel_release", ""),
    )
    live_table.add_row(
        "Root / CAP_SYS_RAWIO", _live_ok(bool(live["has_root"])), "Effective UID 0 required"
    )
    live_table.add_row(
        "/proc/kcore",
        _live_ok(bool(live["kcore_exists"])),
        "Disabled on linux-hardened (CONFIG_PROC_KCORE=n)"
        if live.get("kernel_hardened") and not live["kcore_exists"]
        else "/proc/kcore file found",
    )
    live_table.add_row(
        "LiME module",
        "[green]found[/green]" if live.get("lime_available") else "[yellow]not found[/yellow]",
        live.get("lime_module_path")
        or (
            "Can build: sudo forensiq live --build-lime"
            if live.get("lime_can_build")
            else "lime.ko not found — build from source"
        ),
    )
    live_table.add_row(
        "Kernel ISF",
        "[green]built[/green]" if live.get("linux_isf_available") else "[yellow]not built[/yellow]",
        live.get("linux_isf_path")
        or (
            "Build: sudo forensiq live --build-isf"
            if live.get("linux_isf_can_build")
            else "Required for Volatility 3 Linux analysis"
        ),
    )
    console.print(live_table)

    if live["ready"]:
        console.print("[bold green]Live analysis ready:[/bold green] [cyan]forensiq live[/cyan]")
    elif live.get("lime_available"):
        console.print(
            "[yellow]/proc/kcore unavailable[/yellow] but [green]LiME found[/green] — "
            "run: [cyan]sudo forensiq live --lime[/cyan]"
        )
    elif live.get("lime_can_build"):
        console.print(
            "[yellow]linux-hardened: /proc/kcore disabled.[/yellow]\n"
            "Build tools found. Auto-build LiME: [cyan]sudo forensiq live --build-lime[/cyan]\n"
            "Manual build: [dim]git clone https://github.com/504ensicsLabs/LiME"
            " && make -C LiME/src[/dim]"
        )
    elif live.get("kernel_hardened"):
        console.print(
            "[yellow]linux-hardened: /proc/kcore disabled.[/yellow]\n"
            "Build from source: [cyan]git clone https://github.com/504ensicsLabs/LiME"
            " && make -C LiME/src[/cyan]\n"
            "Then: [cyan]sudo forensiq live --lime --lime-module LiME/src/lime.ko[/cyan]"
        )
    else:
        console.print(
            f"[yellow]Live analysis not available:[/yellow] {live['error']}\n"
            "  Run: [cyan]sudo forensiq live[/cyan]"
        )


# ══════════════════════════════════════════════════════════════════════════════
# forensiq live
# ══════════════════════════════════════════════════════════════════════════════


@app.command("live")
def live(
    output: Path = typer.Option(
        Path("./reports"),
        "--output",
        "-o",
        help="Output directory for the live analysis report.",
    ),
    threshold: float = typer.Option(
        None,
        "--threshold",
        help="Threat score threshold [0.0, 1.0]. Defaults to FORENSIQ_THREAT_THRESHOLD env var.",
    ),
    no_yara: bool = typer.Option(
        False,
        "--no-yara",
        help="Skip YARA rule generation (useful when Ollama is not running).",
    ),
    no_html: bool = typer.Option(
        False,
        "--no-html",
        help="Skip HTML report generation.",
    ),
    use_lime: bool = typer.Option(
        False,
        "--lime",
        help="Acquire memory via LiME kernel module instead of /proc/kcore. "
        "Required on linux-hardened where /proc/kcore is disabled.",
    ),
    build_lime: bool = typer.Option(
        False,
        "--build-lime",
        help="Build LiME from source (clones GitHub repo + make) then acquire memory. "
        "Requires git, make, gcc, and linux-hardened-headers. Saves lime.ko to ~/.forensiq/lime/.",
    ),
    build_isf: bool = typer.Option(
        False,
        "--build-isf",
        help="Generate the Volatility 3 Linux kernel ISF (symbol table) needed to analyze "
        "LiME dumps. Uses BTF (/sys/kernel/btf/vmlinux) + System.map + dwarf2json. "
        "Requires Go (auto-installed). Saves to ~/.cache/volatility3/symbols/linux/.",
    ),
    lime_module: Path | None = typer.Option(
        None,
        "--lime-module",
        help="Explicit path to lime.ko. Auto-detected when omitted.",
        exists=False,
    ),
    lime_output: Path | None = typer.Option(
        None,
        "--lime-dump",
        help="Path for the LiME raw dump file. Defaults to <output>/live_memory.lime.",
    ),
    lime_timeout: int | None = typer.Option(
        None,
        "--lime-timeout",
        help="Maximum seconds the dump may remain stalled (not growing) before "
        "acquisition is aborted. The wait is extended while the dump keeps "
        "growing, so large RAM is never cut off mid-write.",
    ),
    log_level: str = typer.Option(
        "INFO",
        "--log-level",
        "-l",
        help="Log level: DEBUG, INFO, WARNING, ERROR.",
    ),
) -> None:
    """[bold]Analyze live Linux system memory via /proc/kcore or LiME.[/bold]

    Two acquisition paths are available:

    [bold cyan]/proc/kcore[/bold cyan] (default):
      Standard Linux kernel ELF core — available when CONFIG_PROC_KCORE=y.
      Not available on linux-hardened (disabled for security).

    [bold cyan]LiME[/bold cyan] (--lime / --build-lime):
      Linux Memory Extractor loadable kernel module.  Use this on hardened
      kernels where /proc/kcore is unavailable.
      [dim]No AUR package exists — must build from source.[/dim]
      Auto-build: [dim]sudo forensiq live --build-lime[/dim]
      Manual:     [dim]git clone https://github.com/504ensicsLabs/LiME && make -C LiME/src[/dim]

    [yellow]Requirements:[/yellow]
      - Root privileges: [cyan]sudo forensiq live[/cyan]
      - For LiME: lime.ko built for the current kernel release
      - Volatility 3 with a Linux memory ISF symbol table configured
      - XGBoost model trained (run: [cyan]forensiq train[/cyan])

    [red]Security Warning:[/red] Both methods expose ALL physical memory.
    The generated report contains sensitive system data. Handle accordingly.
    """
    configure_logging(log_level=log_level.upper(), log_format="console")

    from forensiq.acquisition.live_memory import (
        _LIME_TIMEOUT_SECONDS,
        LiveMemoryError,
        acquire_lime_dump,
        build_lime_from_source,
        check_live_requirements,
        find_lime_module,
        get_kcore_path,
    )

    status = check_live_requirements(lime_hint=lime_module)

    # ── Auto-build Linux ISF (Volatility 3 symbol table) ─────────────────────
    if build_isf:
        from forensiq.acquisition.linux_isf import build_linux_isf

        console.print("[bold cyan]Building Linux kernel ISF for Volatility 3…[/bold cyan]")
        try:
            isf_path = build_linux_isf(progress_cb=lambda msg: console.print(f"  [dim]{msg}[/dim]"))
            console.print(f"[green]ISF built:[/green] {isf_path}")
        except Exception as exc:
            err_console.print(f"[red]ISF build failed:[/red] {exc}")
            raise typer.Exit(code=2) from exc
        raise typer.Exit(code=0)

    # ── Auto-build LiME from source ───────────────────────────────────────────
    if build_lime:
        if not status["has_root"]:
            err_console.print(
                "[red]Root privileges required for LiME acquisition after build.[/red]\n"
                "Run: [cyan]sudo forensiq live --build-lime[/cyan]"
            )
            raise typer.Exit(code=2)

        console.print("[bold cyan]Building LiME from source…[/bold cyan]")
        try:
            built_path = build_lime_from_source(
                progress_callback=lambda msg: console.print(f"  [dim]{msg}[/dim]")
            )
        except (RuntimeError, LiveMemoryError) as exc:
            err_console.print(f"[red]LiME build failed:[/red] {exc}")
            raise typer.Exit(code=2) from exc

        console.print(f"[green]Built:[/green] {built_path}")
        lime_module = built_path
        use_lime = True
        # Refresh status with the newly built module
        status = check_live_requirements(lime_hint=lime_module)

    # ── LiME acquisition path ─────────────────────────────────────────────────
    if use_lime or (not status["ready"] and status.get("lime_available")):
        if not status["has_root"]:
            err_console.print(
                "[red]Root privileges required for LiME.[/red]\n"
                "Run: [cyan]sudo forensiq live --lime[/cyan]"
            )
            raise typer.Exit(code=2)

        lime_mod = find_lime_module(hint=lime_module)
        if lime_mod is None:
            can_build = status.get("lime_can_build", False)
            build_hint = (
                "Auto-build: [cyan]sudo forensiq live --build-lime[/cyan]\n\n"
                if can_build
                else "Install missing build tools:\n"
                "  [cyan]sudo pacman -S git base-devel linux-hardened-headers[/cyan]\n\n"
            )
            console.print(
                Panel(
                    "[red]LiME module (lime.ko) not found.[/red]\n\n"
                    f"{build_hint}"
                    "Manual build from source:\n"
                    "  [dim]git clone https://github.com/504ensicsLabs/LiME\n"
                    "  make -C LiME/src[/dim]\n\n"
                    "Then use with explicit path:\n"
                    "  [cyan]sudo forensiq live --lime --lime-module LiME/src/lime.ko[/cyan]",
                    border_style="yellow",
                    title="[yellow]LiME Not Found[/yellow]",
                )
            )
            raise typer.Exit(code=2)

        output.mkdir(parents=True, exist_ok=True)
        dump_path = lime_output or (output / "live_memory.lime")

        console.print(
            Panel(
                "[bold cyan]ForensIQ[/bold cyan] Memory Forensics — "
                "[bold red]LIVE MODE (LiME)[/bold red]\n"
                f"[dim]Module:[/dim]  [cyan]{lime_mod}[/cyan]\n"
                f"[dim]Dump:[/dim]    [cyan]{dump_path}[/cyan]\n"
                f"[dim]Output:[/dim]  [cyan]{output}[/cyan]",
                border_style="red",
                padding=(0, 1),
            )
        )

        try:
            dump_path = acquire_lime_dump(
                output_path=dump_path,
                lime_module=lime_mod,
                timeout=_LIME_TIMEOUT_SECONDS if lime_timeout is None else lime_timeout,
            )
        except (LiveMemoryError, PermissionError) as exc:
            err_console.print(f"[red]LiME acquisition failed:[/red] {exc}")
            raise typer.Exit(code=2) from exc

        console.print(
            f"[green]Dump complete:[/green] {dump_path}  "
            f"({dump_path.stat().st_size / 1_048_576:.0f} MB)\n"
        )
        dump_source = dump_path

    # ── /proc/kcore path ──────────────────────────────────────────────────────
    else:
        if not status["ready"]:
            # Build a helpful, context-aware error message
            advice = ""
            if status.get("kernel_hardened"):
                if status.get("lime_can_build"):
                    advice = (
                        "\n\n[yellow]linux-hardened disables CONFIG_PROC_KCORE.[/yellow]\n"
                        "Build tools available. Run: [cyan]sudo forensiq live --build-lime[/cyan]"
                    )
                else:
                    advice = (
                        "\n\n[yellow]linux-hardened disables CONFIG_PROC_KCORE.[/yellow]\n"
                        "Build LiME: [dim]git clone https://github.com/504ensicsLabs/LiME"
                        " && make -C LiME/src[/dim]\n"
                        "Then use:   [cyan]sudo forensiq live --lime "
                        "--lime-module LiME/src/lime.ko[/cyan]"
                    )
            console.print(
                Panel(
                    f"[red]Live memory analysis not available:[/red]\n\n"
                    f"{status['error']}{advice}\n\n"
                    "[dim]Run [cyan]forensiq check[/cyan] for full diagnostic.[/dim]",
                    border_style="red",
                    title="[red]Live Analysis Error[/red]",
                )
            )
            raise typer.Exit(code=2)

        try:
            dump_source = get_kcore_path()
        except LiveMemoryError as exc:
            err_console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=2) from exc

        console.print(
            Panel(
                "[bold cyan]ForensIQ[/bold cyan] Memory Forensics — "
                "[bold red]LIVE MODE (/proc/kcore)[/bold red]\n"
                f"[dim]Source:[/dim] [cyan]{dump_source}[/cyan]  "
                f"[dim](live Linux kernel memory)[/dim]\n"
                f"[dim]Output:[/dim] [cyan]{output}[/cyan]",
                border_style="red",
                padding=(0, 1),
            )
        )

    # ── Analysis pipeline (shared for both paths) ─────────────────────────────
    from forensiq.pipeline.analysis_pipeline import AnalysisPipeline

    pipeline = AnalysisPipeline(
        show_progress=True,
        generate_yara=not no_yara,
        generate_html=not no_html,
        generate_json=True,
        force_reanalyze=True,
    )

    try:
        result = asyncio.run(
            pipeline.run(
                dump_path=dump_source,
                output_dir=output,
                threshold=threshold,
            )
        )
    except KeyboardInterrupt:
        err_console.print("\n[yellow]Live analysis interrupted by user.[/yellow]")
        raise typer.Exit(code=2) from None
    except Exception as exc:
        err_console.print(f"[red]Fatal error during live analysis:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    if result.exit_code == 2:
        err_console.print(f"[red]Live analysis failed:[/red] {result.error}")
        _print_troubleshooting_hint()
        raise typer.Exit(code=2)

    if result.report is None:
        err_console.print("[red]Error:[/red] No report generated.")
        raise typer.Exit(code=2)

    _print_summary(result.report, result)
    raise typer.Exit(code=result.exit_code)


# ══════════════════════════════════════════════════════════════════════════════
# forensiq diff
# ══════════════════════════════════════════════════════════════════════════════


@app.command("diff")
def diff_cmd(
    before: Path = typer.Option(
        ...,
        "--before",
        help="Path to the BEFORE memory dump (baseline).",
    ),
    after: Path = typer.Option(
        ...,
        "--after",
        help="Path to the AFTER memory dump (post-incident).",
    ),
    output: Path = typer.Option(
        Path("./reports"),
        "--output",
        "-o",
        help="Output directory for the diff report.",
    ),
    log_level: str = typer.Option(
        "INFO",
        "--log-level",
        "-l",
        help="Log level: DEBUG, INFO, WARNING, ERROR.",
    ),
) -> None:
    """[bold]Compare two memory dumps and show what changed.[/bold]

    Both dumps are extracted concurrently for efficiency. The diff
    identifies:

    \b
      • New processes (appeared after the incident)
      • Disappeared processes (killed/replaced)
      • Changed processes (new DLLs, connections, injections)
      • New network connections per process
      • New DLLs loaded per process
      • New malfind (injection) regions
      • New RWX VAD regions (shellcode indicators)

    Output is written as a JSON file to the --output directory and
    summarized as a table in the console.
    """
    configure_logging(log_level=log_level.upper(), log_format="console")

    for p, label in [(before, "before"), (after, "after")]:
        if not p.exists():
            err_console.print(f"[red]Error:[/red] Dump file not found: {p} ({label})")
            raise typer.Exit(code=2)

    console.print(
        Panel(
            "[bold cyan]ForensIQ[/bold cyan] Memory Dump Diff\n"
            f"[dim]Before:[/dim] [cyan]{before}[/cyan]\n"
            f"[dim]After:[/dim]  [cyan]{after}[/cyan]\n"
            f"[dim]Output:[/dim] [cyan]{output}[/cyan]",
            border_style="cyan",
            padding=(0, 1),
        )
    )

    from forensiq.pipeline.diff_pipeline import DiffPipeline

    try:
        result = asyncio.run(
            DiffPipeline().run(
                before_path=before,
                after_path=after,
                output_dir=output,
            )
        )
    except KeyboardInterrupt:
        err_console.print("\n[yellow]Diff interrupted.[/yellow]")
        raise typer.Exit(code=2) from None
    except Exception as exc:
        err_console.print(f"[red]Fatal error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    if result.exit_code == 2:
        err_console.print(f"[red]Diff failed:[/red] {result.error}")
        raise typer.Exit(code=2)

    # ── Print summary table ───────────────────────────────────────────────────
    diff_table = Table(
        title="Memory Diff Summary",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        padding=(0, 1),
    )
    diff_table.add_column("Category", style="bold", width=26)
    diff_table.add_column("Count", width=8)
    diff_table.add_column("Processes")

    def _pids_str(procs: list) -> str:
        return ", ".join(f"{p.name}({p.pid})" for p in procs[:10]) + (
            f" … +{len(procs) - 10} more" if len(procs) > 10 else ""
        )

    diff_table.add_row(
        "[green]New processes[/green]",
        f"[green]{len(result.new_processes)}[/green]",
        _pids_str(result.new_processes),
    )
    diff_table.add_row(
        "[red]Disappeared processes[/red]",
        f"[red]{len(result.disappeared_processes)}[/red]",
        _pids_str(result.disappeared_processes),
    )
    diff_table.add_row(
        "[yellow]Changed processes[/yellow]",
        f"[yellow]{len(result.changed_processes)}[/yellow]",
        _pids_str(result.changed_processes),
    )
    console.print(diff_table)

    # Changed process details
    if result.changed_processes:
        detail_table = Table(
            title="Changed Process Details",
            box=box.SIMPLE,
            show_header=True,
            header_style="bold yellow",
            padding=(0, 1),
        )
        detail_table.add_column("PID", width=7)
        detail_table.add_column("Process", width=20)
        detail_table.add_column("New Conns", width=10)
        detail_table.add_column("New DLLs", width=10)
        detail_table.add_column("New Injections", width=15)
        detail_table.add_column("New RWX VADs", width=13)

        for pd in result.changed_processes:
            detail_table.add_row(
                str(pd.pid),
                pd.name,
                str(len(pd.new_connections)),
                str(len(pd.new_dlls)),
                str(pd.new_malfind_regions),
                str(pd.new_rwx_vads),
            )
        console.print(detail_table)

    if result.output_json:
        console.print(f"\n[dim]Diff report saved:[/dim] [cyan]{result.output_json}[/cyan]")

    raise typer.Exit(code=0)


# ══════════════════════════════════════════════════════════════════════════════
# forensiq menu
# ══════════════════════════════════════════════════════════════════════════════


@app.command("menu")
def menu() -> None:
    """[bold]Launch the interactive TUI console menu.[/bold]

    Provides a guided wizard interface to all ForensIQ features:
      - Analyze a memory dump (with step-by-step option prompts)
      - Live memory analysis (/proc/kcore)
      - Compare two memory dumps (diff)
      - View analysis history
      - System requirements check

    [dim]Tip:[/dim] All options are accessible via CLI flags too (run [cyan]forensiq --help[/cyan]).
    """
    try:
        from forensiq.tui.menu import run_menu

        run_menu()
    except ImportError as exc:
        err_console.print(
            f"[red]Error:[/red] TUI requires questionary: pip install questionary\n{exc}"
        )
        raise typer.Exit(code=2) from exc
    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted.[/dim]")


# ══════════════════════════════════════════════════════════════════════════════
# forensiq version
# ══════════════════════════════════════════════════════════════════════════════


@app.command("version")
def version() -> None:
    """[bold]Print ForensIQ version and component information.[/bold]"""
    import importlib.metadata
    import subprocess

    try:
        fiq_version = importlib.metadata.version("forensiq")
    except Exception:
        fiq_version = "dev"

    from forensiq.config.settings import get_settings

    settings = get_settings()

    vol_version = "not found"
    try:
        proc = subprocess.run(
            [settings.get_volatility_executable(), "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        vol_version = (proc.stdout or proc.stderr or "").strip().split("\n")[0]
    except Exception:  # noqa: S110
        pass  # vol3 may not be installed; version display is optional

    import sys as _sys

    python_version = (
        f"{_sys.version_info.major}.{_sys.version_info.minor}.{_sys.version_info.micro}"
    )

    model_path = settings.get_model_path()
    model_info = "not trained"
    if settings.is_model_available():
        meta_path = model_path.with_suffix(".json")
        if meta_path.exists():
            import json

            try:
                with meta_path.open() as f:
                    meta = json.load(f)
                model_info = (
                    f"trained {meta.get('trained_at', '?')} | roc_auc={meta.get('roc_auc', '?')}"
                )
            except Exception:
                model_info = f"available at {model_path}"
        else:
            model_info = f"available at {model_path}"

    # Best-effort, non-blocking: show the resolved model when Ollama is up,
    # otherwise just the configured one.  Never let a downed server block
    # the version command.
    ollama_model_display = settings.OLLAMA_MODEL
    try:
        from forensiq.llm.ollama_client import OllamaClient

        resolved = asyncio.run(
            OllamaClient(
                base_url=settings.OLLAMA_BASE_URL,
                model=settings.OLLAMA_MODEL,
                timeout=2,
            ).resolve_model()
        )
        if resolved and resolved != settings.OLLAMA_MODEL:
            ollama_model_display = f"{settings.OLLAMA_MODEL} (using {resolved})"
    except Exception:  # noqa: S110
        pass  # best-effort; never let a downed server block version output

    console.print(
        Panel(
            f"[bold cyan]ForensIQ[/bold cyan]  v{fiq_version}\n\n"
            f"[dim]Python:[/dim]      {python_version}\n"
            f"[dim]Volatility 3:[/dim] {vol_version}\n"
            f"[dim]ML Model:[/dim]    {model_info}\n"
            f"[dim]Ollama URL:[/dim]  {settings.OLLAMA_BASE_URL}\n"
            f"[dim]Ollama Model:[/dim] {ollama_model_display}",
            title="[bold]Version Information[/bold]",
            border_style="cyan",
            padding=(0, 1),
        )
    )
