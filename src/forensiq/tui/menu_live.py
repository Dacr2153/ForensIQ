# FILE: src/forensiq/tui/menu_live.py
"""Live memory analysis sub-menu for the ForensIQ TUI.

Contains the interactive wizard for live analysis via /proc/kcore or LiME,
plus the pipeline runner wrappers that drive the live acquisition path.
Shared UI helpers (console, prompts) are imported from forensiq.tui.menu.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rich import box
from rich.panel import Panel
from rich.table import Table

from forensiq.tui.menu import (
    _ask_confirm,
    _ask_output_dir,
    _print_report_summary,
    _run_pipeline_with_progress,
    _separator,
    console,
    err_console,
)


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
            "[dim]Checks system prerequisites then acquires and analyzes the running\n"
            "Linux kernel memory. Two acquisition methods are supported:\n"
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
            "[yellow]Note:[/yellow] This linux-hardened kernel has /proc/kcore disabled\n"
            "(security policy).\n"
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
                "[yellow]Kernel ISF not built yet[/yellow] — Volatility 3 needs it to\n"
                "analyze the LiME dump.\n"
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
                except Exception as exc:
                    err_console.print(f"[red]ISF build failed:[/red] {exc}")
                    console.print(
                        "[yellow]Analysis will proceed but Volatility 3 plugins may\n"
                        "fail.[/yellow]\n"
                        "[dim]Run manually: sudo forensiq live --build-isf[/dim]"
                    )
        else:
            console.print(
                "[yellow]Kernel ISF not available.[/yellow] Volatility 3 Linux analysis may fail.\n"
                "[dim]Build requires: BTF (/sys/kernel/btf/vmlinux) + System.map + Go +\n"
                "dwarf2json[/dim]"
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
            "memory, and kernel internals. Treat the dump file as a high-confidentiality\n"
            "artifact.\n\n"
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

    output_dir = _ask_output_dir("Output directory for reports:", default="./reports")
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


def _run_live_kcore(reqs: dict[str, Any]) -> None:
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

    output_dir = _ask_output_dir("Output directory for reports:", default="./reports")
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
