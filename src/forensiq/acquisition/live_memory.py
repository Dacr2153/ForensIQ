# FILE: src/forensiq/acquisition/live_memory.py
"""Live memory acquisition for Linux systems via /proc/kcore or LiME.

Two acquisition paths are supported:

  1. /proc/kcore  — The kernel's ELF core dump of physical memory.
     Available on kernels compiled with CONFIG_PROC_KCORE=y (the default on
     most distros). Disabled on linux-hardened for security reasons.

  2. LiME (Linux Memory Extractor) — A loadable kernel module (LKM) that
     exposes raw physical memory via a network socket or file path.  The gold
     standard for live forensic acquisition when /proc/kcore is unavailable.
     https://github.com/504ensicsLabs/LiME

Build LiME for linux-hardened (no AUR package exists — must build from source):
  sudo pacman -S linux-hardened-headers   # if not already installed
  git clone https://github.com/504ensicsLabs/LiME /tmp/LiME
  make -C /tmp/LiME/src
  # lime.ko is now at /tmp/LiME/src/lime.ko

  Or let ForensIQ build it automatically:
  sudo forensiq live --build-lime

Notes on module signing (linux-hardened):
  CONFIG_MODULE_SIG=y but CONFIG_MODULE_SIG_FORCE=n → unsigned modules load
  with a kernel taint warning but are otherwise functional.
  Lockdown in [none] mode → no additional restrictions.

Requirements:
  - /proc/kcore path: Linux 2.6+ with CONFIG_PROC_KCORE=y + root
  - LiME path: lime.ko built for the EXACT current kernel release + root

Security Notes:
  - Both methods expose all physical memory — treat output with utmost care.
  - Always run in an isolated analysis environment.
  - LiME dumps may be very large (equals total installed RAM).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from forensiq.utils.logger import get_logger

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KCORE_PATH: Path = Path("/proc/kcore")

# Minimum ELF header size expected in /proc/kcore
_KCORE_MIN_BYTES: int = 4096

# LiME dump format written to disk (raw physical pages + LiME 8-byte headers)
LIME_FORMAT: str = "lime"

# All formats accepted by the LiME kernel module
_VALID_LIME_FORMATS: frozenset[str] = frozenset({"lime", "raw", "padded"})

# LiME upstream repository
LIME_REPO_URL: str = "https://github.com/504ensicsLabs/LiME"

# Default directory for the ForensIQ-built LiME module
_FORENSIQ_LIME_DIR: Path = Path.home() / ".forensiq" / "lime"


def _safe_kernel_release(release: str) -> str:
    """Return a filesystem-safe form of a kernel release string.

    A kernel release must never contain ``/``, but we replace any path
    separator defensively so a crafted/odd release string cannot traverse
    directories when used in a file or cache path.
    """
    return release.replace("/", "-")


_KERNEL_RELEASE = _safe_kernel_release(os.uname().release)

# Candidate locations where a pre-built LiME module might live.
# Ordered from most-specific (current kernel) to most-generic.
# SECURITY: only trusted, system-level or ForensIQ-owned paths are searched.
# CWD and $HOME are deliberately excluded — a planted lime.ko in a directory
# (or a downloaded attachment) must never be auto-loaded into the kernel as
# root.  Use --lime-module with an explicit path for such modules.
_LIME_SEARCH_PATHS: list[Path] = [
    # ForensIQ-built module (kernel-specific)
    _FORENSIQ_LIME_DIR / f"lime-{_KERNEL_RELEASE}.ko",
    # Generic fallback in ForensIQ dir
    _FORENSIQ_LIME_DIR / "lime.ko",
    # System-wide installations
    Path(f"/usr/lib/lime/lime-{_KERNEL_RELEASE}.ko"),
    Path(f"/lib/modules/{_KERNEL_RELEASE}/misc/lime.ko"),
    Path(f"/lib/modules/{_KERNEL_RELEASE}/extra/lime.ko"),
    Path("/usr/lib/lime/lime.ko"),
    Path("/usr/local/lib/lime/lime.ko"),
    Path("/opt/lime/lime.ko"),
]

# Maximum seconds to wait for the LiME dump file to appear / grow stable.
# This is a *stall* timeout: while the dump keeps growing the deadline is
# extended, so a large RAM acquisition is never aborted mid-write.  It only
# fails when the file has stopped growing past the deadline.
_LIME_TIMEOUT_SECONDS: int = 300

# Poll interval while waiting for LiME to finish writing the dump
_LIME_POLL_INTERVAL: float = 2.0


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class LiveMemoryError(Exception):
    """Raised when live memory acquisition preconditions are not met."""


# ---------------------------------------------------------------------------
# Kernel introspection helpers
# ---------------------------------------------------------------------------


def get_kernel_info() -> dict[str, str]:
    """Return basic kernel identification information.

    Reads ``/proc/version`` (always present) and optionally the kernel
    build config to detect hardened / vanilla / custom builds.

    Returns:
        Dict with keys:
            - ``release`` (str): Kernel release string (``uname -r``)
            - ``version`` (str): Full ``/proc/version`` string (first line)
            - ``is_hardened`` (bool-ish str): "true"/"false" — linux-hardened
            - ``kcore_compiled_in`` (str): "true"/"false"/"unknown"
    """
    release = os.uname().release

    # Read /proc/version safely
    try:
        version_line = (
            Path("/proc/version").read_text(encoding="utf-8", errors="replace").splitlines()[0]
        )
    except OSError:
        version_line = release

    # Detect hardened kernel
    is_hardened = "hardened" in release.lower() or "hardened" in version_line.lower()

    # Try to determine CONFIG_PROC_KCORE from kernel config
    kcore_compiled: str = "unknown"
    config_sources: list[Path] = [
        Path("/proc/config.gz"),  # gzip compressed — requires zcat
        Path(f"/boot/config-{release}"),
        Path("/boot/config"),
    ]
    for src in config_sources:
        if not src.exists():
            continue
        try:
            if src.suffix == ".gz":
                result = subprocess.run(
                    ["zcat", str(src)], capture_output=True, text=True, timeout=5
                )
                config_text = result.stdout
            else:
                config_text = src.read_text(encoding="utf-8", errors="replace")

            for line in config_text.splitlines():
                line = line.strip()
                if line.startswith("CONFIG_PROC_KCORE"):
                    if "=y" in line or "=m" in line:
                        kcore_compiled = "true"
                    else:
                        kcore_compiled = "false"
                    break
            break
        except (OSError, subprocess.TimeoutExpired):
            continue

    return {
        "release": release,
        "version": version_line,
        "is_hardened": str(is_hardened).lower(),
        "kcore_compiled_in": kcore_compiled,
    }


# ---------------------------------------------------------------------------
# LiME support
# ---------------------------------------------------------------------------


def check_lime_build_requirements() -> dict[str, bool | str]:
    """Check whether LiME can be built from source on this system.

    Returns:
        Dict with keys:
            - ``git_available`` (bool): git executable found
            - ``make_available`` (bool): make executable found
            - ``gcc_available`` (bool): gcc executable found
            - ``headers_available`` (bool): kernel headers build dir exists
            - ``headers_path`` (str): path to the kernel headers build dir
            - ``can_build`` (bool): True if all build tools are present
    """
    release = os.uname().release
    build_dir = Path(f"/lib/modules/{release}/build")

    git_ok = shutil.which("git") is not None
    make_ok = shutil.which("make") is not None
    gcc_ok = shutil.which("gcc") is not None
    headers_ok = (build_dir / "Makefile").is_file()

    return {
        "git_available": git_ok,
        "make_available": make_ok,
        "gcc_available": gcc_ok,
        "headers_available": headers_ok,
        "headers_path": str(build_dir),
        "can_build": git_ok and make_ok and gcc_ok and headers_ok,
    }


def build_lime_from_source(
    install_dir: Path | None = None,
    *,
    progress_callback: Callable[[str], None] | None = None,
) -> Path:
    """Clone LiME from GitHub and build lime.ko for the current kernel.

    Uses the kernel headers already installed at
    ``/lib/modules/<release>/build``.  Does NOT require root — building is
    done as the current user.  The resulting ``lime.ko`` is copied to
    ``install_dir`` (default: ``~/.forensiq/lime/``) and named
    ``lime-<kernel-release>.ko`` so multiple kernel versions can coexist.

    Args:
        install_dir: Directory to store the compiled ``lime.ko``.
            Defaults to ``~/.forensiq/lime/``.
        progress_callback: Optional ``callable(message: str)`` called with
            status messages during the build.

    Returns:
        Path to the compiled ``lime-<release>.ko`` module.

    Raises:
        LiveMemoryError: If any build step fails.
        RuntimeError: If build tools or kernel headers are missing.
    """

    def _emit(msg: str) -> None:
        if progress_callback is not None:
            progress_callback(msg)

    # ── Pre-flight ────────────────────────────────────────────────────────────
    reqs = check_lime_build_requirements()
    if not reqs["can_build"]:
        missing = [k for k in ("git", "make", "gcc") if not reqs[f"{k}_available"]]
        if not reqs["headers_available"]:
            missing.append("linux-hardened-headers (sudo pacman -S linux-hardened-headers)")
        raise RuntimeError(f"Cannot build LiME — missing: {', '.join(missing)}")

    release = os.uname().release
    dest_dir = install_dir or _FORENSIQ_LIME_DIR
    dest_dir.mkdir(parents=True, exist_ok=True)
    final_path = dest_dir / f"lime-{_safe_kernel_release(release)}.ko"

    # If already built for this kernel, return immediately
    if final_path.is_file() and final_path.stat().st_size > 0:
        _emit(f"LiME already built for {release}: {final_path}")
        return final_path

    # ── Clone ────────────────────────────────────────────────────────────────
    with tempfile.TemporaryDirectory(prefix="forensiq-lime-") as tmpdir:
        clone_dir = Path(tmpdir) / "LiME"
        _emit(f"Cloning LiME from {LIME_REPO_URL} …")

        clone_result = subprocess.run(
            ["git", "clone", "--depth=1", LIME_REPO_URL, str(clone_dir)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if clone_result.returncode != 0:
            raise LiveMemoryError(
                f"git clone failed: {clone_result.stderr.strip()}\n"
                "Check network connectivity and try again."
            )

        # ── Build ─────────────────────────────────────────────────────────────
        src_dir = clone_dir / "src"
        _emit(f"Building lime.ko for kernel {release} …")

        make_result = subprocess.run(
            ["make"],
            cwd=str(src_dir),
            capture_output=True,
            text=True,
            timeout=180,
        )
        if make_result.returncode != 0:
            raise LiveMemoryError(
                f"make failed (exit {make_result.returncode}):\n"
                f"{make_result.stderr[-1500:].strip()}"
            )

        # ── Install ───────────────────────────────────────────────────────────
        # LiME's Makefile may produce different filenames depending on the
        # kernel and distribution:
        #   • lime.ko               — plain (no compression)
        #   • lime-<release>.ko     — named with kernel version (common)
        #   • lime.ko.zst / .xz / .gz — compressed (CONFIG_MODULE_COMPRESS_*)
        #   • lime-<release>.ko.zst — named + compressed
        # Skip hidden build-system files like .lime.ko.cmd.
        built_ko: Path | None = None

        # Priority: exact well-known names first, then glob for lime*.ko*
        exact_candidates = [
            src_dir / "lime.ko",
            src_dir / f"lime-{release}.ko",
            src_dir / "lime.ko.zst",
            src_dir / f"lime-{release}.ko.zst",
            src_dir / "lime.ko.xz",
            src_dir / f"lime-{release}.ko.xz",
            src_dir / "lime.ko.gz",
            src_dir / f"lime-{release}.ko.gz",
        ]
        for candidate in exact_candidates:
            if candidate.is_file():
                built_ko = candidate
                break

        # Fallback: any non-hidden file whose name contains ".ko"
        if built_ko is None:
            for candidate in sorted(src_dir.iterdir()):
                if (
                    not candidate.name.startswith(".")
                    and ".ko" in candidate.name
                    and candidate.is_file()
                ):
                    built_ko = candidate
                    break

        if built_ko is None:
            present = sorted(f.name for f in src_dir.iterdir() if ".ko" in f.name)
            raise LiveMemoryError(
                f"Build succeeded (exit 0) but no lime*.ko found in {src_dir}.\n"
                f"Files with .ko in name: {', '.join(present) or '(none)'}\n"
                "This is unexpected — check make output."
            )

        # Decompress compressed modules so insmod can load them
        if built_ko.suffix in (".zst", ".xz", ".gz"):
            decompressed = src_dir / "lime.ko"
            _emit(f"Decompressing {built_ko.name} → lime.ko …")
            if built_ko.suffix == ".zst":
                decomp: subprocess.CompletedProcess[bytes] = subprocess.run(
                    ["zstd", "-d", str(built_ko), "-o", str(decompressed), "--force"],
                    capture_output=True,
                    timeout=30,
                )
            elif built_ko.suffix == ".xz":
                # Binary mode: kernel modules are not valid UTF-8 — decoding via
                # text=True would corrupt the bytes or raise UnicodeDecodeError.
                decomp = subprocess.run(
                    ["xz", "-d", str(built_ko), "--stdout"],
                    capture_output=True,
                    timeout=30,
                )
                if decomp.returncode == 0:
                    decompressed.write_bytes(decomp.stdout)
            else:  # .gz
                import gzip

                with gzip.open(str(built_ko), "rb") as _gz:
                    decompressed.write_bytes(_gz.read())
                decomp = subprocess.CompletedProcess([], 0)

            if decomp.returncode != 0:
                err = (decomp.stderr or b"").decode(errors="replace")
                raise LiveMemoryError(f"Failed to decompress {built_ko.name}: {err.strip()}")
            built_ko = decompressed

        shutil.copy2(str(built_ko), str(final_path))
        _emit(f"LiME installed: {final_path}")

    return final_path


def find_lime_module(hint: Path | None = None) -> Path | None:
    """Search for a pre-built LiME kernel module.

    Args:
        hint: Optional explicit path to lime.ko supplied by the user.

    Returns:
        Path to the LiME module if found, else ``None``.
    """
    candidates: list[Path] = []
    if hint is not None:
        candidates.append(hint.expanduser().resolve())
    candidates.extend(_LIME_SEARCH_PATHS)

    for path in candidates:
        if path.is_file() and os.access(path, os.R_OK):
            return path
    return None


def _handle_insmod_error(proc: subprocess.CompletedProcess[str], output_path: Path) -> None:
    """Raise an appropriate LiveMemoryError based on insmod's exit status."""
    stderr = proc.stderr.strip()
    if "File exists" in stderr or "EEXIST" in stderr:
        if not output_path.exists() or output_path.stat().st_size == 0:
            raise LiveMemoryError(
                "LiME module is already loaded but the dump file is missing. "
                "Unload it first: sudo rmmod lime"
            )
        return  # Dump already exists from a prior run — treat as complete
    if "Required key not available" in stderr or "Operation not permitted" in stderr:
        raise LiveMemoryError(
            "LiME module rejected by the kernel — module signing enforcement "
            "is active (Secure Boot or CONFIG_MODULE_SIG_FORCE=y).\n"
            "Either disable Secure Boot, sign lime.ko, or build LiME with "
            "your kernel's signing key.\n"
            f"insmod error: {stderr}"
        )
    raise LiveMemoryError(f"insmod failed (exit {proc.returncode}): {stderr}")


def acquire_lime_dump(
    output_path: Path,
    lime_module: Path,
    *,
    lime_format: str = LIME_FORMAT,
    timeout: int = _LIME_TIMEOUT_SECONDS,
) -> Path:
    """Acquire a live memory dump using the LiME kernel module.

    Loads ``lime_module`` via ``insmod`` with ``path=<output_path>
    format=<lime_format>`` and waits for the dump file to be fully written
    (detected when the file size stops growing).

    Args:
        output_path: Destination file for the memory dump (e.g. ``/tmp/live.lime``).
        lime_module: Path to the compiled ``lime.ko`` LKM.
        lime_format: LiME output format — ``"lime"`` (default), ``"raw"``, or
            ``"padded"``.  ``"lime"`` is the safest choice: it adds 8-byte
            per-segment headers that Volatility 3 understands.
        timeout: Maximum seconds the dump may remain stalled (not growing)
            before acquisition is abandoned.  The deadline is extended while
            the dump keeps growing, so large RAM is never cut off mid-write.

    Returns:
        ``output_path`` after the dump is fully written.

    Raises:
        LiveMemoryError: If insmod fails, root is not available, or the dump
            file stops growing for ``timeout`` seconds.
        PermissionError: Re-raised when the caller is not root.
    """
    if os.geteuid() != 0:
        raise PermissionError(
            "LiME acquisition requires root privileges. Run: sudo forensiq live --lime"
        )

    if lime_format not in _VALID_LIME_FORMATS:
        raise LiveMemoryError(
            f"Invalid LiME format: {lime_format!r}. "
            f"Must be one of: {', '.join(sorted(_VALID_LIME_FORMATS))}"
        )

    if not lime_module.is_file():
        raise LiveMemoryError(f"LiME module not found: {lime_module}")

    # ── Security: refuse unsafe output paths before touching the kernel ─────
    # A memory dump is written by kernel code running as root.  If the output
    # path is a symlink or an existing non-empty file, a local attacker could
    # redirect root's write into an arbitrary file (or clobber a real one).
    if output_path.is_symlink():
        raise LiveMemoryError(
            f"Refusing symlink at output path: {output_path}. "
            "Remove the symlink or choose a different output path."
        )
    if output_path.exists() and output_path.stat().st_size > 0:
        raise LiveMemoryError(
            f"Refusing to overwrite existing non-empty file: {output_path}. "
            "Remove it first or choose a different output path."
        )

    # Create the output directory with private permissions when we create it,
    # so a partial dump is never world-readable during acquisition.
    parent = output_path.parent
    try:
        created_parent = not parent.exists()
        parent.mkdir(parents=True, exist_ok=True)
        if created_parent:
            parent.chmod(0o700)
    except OSError as exc:
        raise LiveMemoryError(
            f"Cannot create output directory {parent}: {exc}"
        ) from exc

    # insmod requires each module parameter as a separate argv element.
    # Passing them joined in one string causes "Invalid parameters".
    insmod_cmd = [
        "insmod",
        str(lime_module),
        f"path={output_path}",
        f"format={lime_format}",
    ]

    # LiME's insmod BLOCKS until the entire memory dump is written — unlike
    # a normal module load.  We must run it in a background thread and poll
    # for file-size stability rather than waiting for subprocess to return.
    import threading

    insmod_result: dict[str, Any] = {}
    insmod_exc: list[Exception] = []

    def _run_insmod() -> None:
        try:
            r = subprocess.run(
                insmod_cmd,
                capture_output=True,
                text=True,
            )
            insmod_result["proc"] = r
        except FileNotFoundError as exc:
            insmod_exc.append(exc)
        except Exception as exc:
            insmod_exc.append(exc)

    thread = threading.Thread(target=_run_insmod, daemon=True)
    thread.start()

    # The module must NEVER be left loaded after we return — a loaded LiME
    # module keeps mapping physical memory (a security risk to the user's
    # machine) and blocks a re-run.  The finally block guarantees rmmod on
    # every exit path: success, timeout, error, and KeyboardInterrupt.
    try:
        # Give insmod a moment to fail fast (bad params, missing module, etc.)
        thread.join(timeout=3)
        if insmod_exc:
            insmod_error = insmod_exc[0]
            if isinstance(insmod_error, FileNotFoundError):
                raise LiveMemoryError(
                    "'insmod' not found. Install kmod (e.g. pacman -S kmod)."
                )
            raise LiveMemoryError(f"insmod error: {insmod_error}")

        # Check if it already finished with an error (e.g. "Invalid parameters")
        if not thread.is_alive():
            proc = insmod_result.get("proc")
            if proc is not None and proc.returncode != 0:
                _handle_insmod_error(proc, output_path)

        # Poll until the dump file appears and stops growing.  The timeout is
        # a *stall* timeout: it only fires when the file has not grown for
        # `timeout` seconds, so a large acquisition is never aborted while it
        # is still making progress.
        last_growth = time.monotonic()
        prev_size: int = -1
        stable_count: int = 0

        def _abort_stalled() -> None:
            # Best-effort cleanup: remove any partial dump so it cannot be
            # mistaken for a full one.  The module itself is unloaded in the
            # finally block below.
            try:
                if output_path.exists():
                    output_path.unlink()
            except OSError:
                pass
            raise LiveMemoryError(
                f"Timed out ({timeout}s without growth) waiting for LiME "
                f"dump at {output_path}. The partial dump was removed and the "
                "LiME module unloaded. Re-run acquisition if you want to retry."
            )

        if timeout <= 0:
            _abort_stalled()

        # Lock the dump down to 0600 as soon as the file first appears, so the
        # partial dump is never left world-readable while it is being written.
        permissions_locked = False

        def _lock_permissions() -> None:
            nonlocal permissions_locked
            if permissions_locked:
                return
            try:
                output_path.chmod(0o600)
                permissions_locked = True
            except OSError as exc:
                log.warning(
                    "Could not restrict permissions on partial dump",
                    path=str(output_path),
                    error=str(exc),
                )

        while True:
            if output_path.exists():
                _lock_permissions()
                current_size = output_path.stat().st_size
                if current_size > 0 and current_size == prev_size:
                    stable_count += 1
                    if stable_count >= 3:
                        # Size stable for 3 consecutive polls — dump complete
                        break
                else:
                    stable_count = 0
                if current_size > prev_size:
                    last_growth = time.monotonic()
                prev_size = current_size

            # Re-check for early insmod failure
            if not thread.is_alive() and insmod_exc:
                raise LiveMemoryError(f"insmod error: {insmod_exc[0]}")
            if not thread.is_alive():
                proc = insmod_result.get("proc")
                if proc is not None and proc.returncode != 0:
                    _handle_insmod_error(proc, output_path)
                # insmod returned 0 and thread exited — check dump exists
                if output_path.exists() and output_path.stat().st_size > 0:
                    break

            # A dump that keeps growing is progress: only abort when the file
            # has been static for the full timeout window.
            if time.monotonic() - last_growth >= timeout:
                _abort_stalled()

            time.sleep(_LIME_POLL_INTERVAL)
    finally:
        # Always wait for insmod to finish and unload the module, no matter how
        # this function exits.  rmmod fails harmlessly if the module never loaded.
        thread.join(timeout=10)
        try:
            subprocess.run(["rmmod", "lime"], capture_output=True, timeout=10)
        except Exception:  # noqa: S110
            pass  # Best-effort: never mask the original result

    # A memory dump is highly sensitive: lock down permissions so it can only
    # be read by the acquiring user, even if the parent directory is lax.
    try:
        output_path.chmod(0o600)
    except OSError as exc:
        log.warning(
            "Could not restrict permissions on memory dump",
            path=str(output_path),
            error=str(exc),
        )

    return output_path


# ---------------------------------------------------------------------------
# /proc/kcore checks
# ---------------------------------------------------------------------------


def check_live_requirements(lime_hint: Path | None = None) -> dict[str, Any]:
    """Check all preconditions for live memory analysis.

    Checks both /proc/kcore and LiME availability so callers can offer the
    user whichever path is feasible.

    Args:
        lime_hint: Optional explicit path to lime.ko for the LiME check.

    Returns:
        Dict with keys:

        Core checks (always present):
            - ``is_linux`` (bool)
            - ``has_root`` (bool)
            - ``ready`` (bool): True only if /proc/kcore is fully accessible
            - ``error`` (str): Human-readable error when ``ready`` is False

        /proc/kcore checks:
            - ``kcore_exists`` (bool)
            - ``kcore_readable`` (bool)
            - ``kcore_size_ok`` (bool)

        LiME checks:
            - ``lime_available`` (bool): lime.ko found on disk
            - ``lime_module_path`` (str | None): path to lime.ko if found

        Kernel info:
            - ``kernel_release`` (str)
            - ``kernel_hardened`` (bool): linux-hardened detected
            - ``kcore_compiled_in`` (str): "true"/"false"/"unknown"
    """
    status: dict[str, Any] = {
        "is_linux": False,
        "kcore_exists": False,
        "kcore_readable": False,
        "has_root": False,
        "kcore_size_ok": False,
        "lime_available": False,
        "lime_module_path": None,
        "lime_can_build": False,
        "linux_isf_available": False,
        "linux_isf_path": None,
        "linux_isf_can_build": False,
        "kernel_release": "",
        "kernel_hardened": False,
        "kcore_compiled_in": "unknown",
        "ready": False,
        "error": "",
    }

    # ── OS check ──────────────────────────────────────────────────────────────
    status["is_linux"] = os.name == "posix" and os.uname().sysname == "Linux"
    if not status["is_linux"]:
        status["error"] = "Live analysis requires Linux. This system is not Linux."
        return status

    # ── Kernel info ───────────────────────────────────────────────────────────
    kinfo = get_kernel_info()
    status["kernel_release"] = kinfo["release"]
    status["kernel_hardened"] = kinfo["is_hardened"] == "true"
    status["kcore_compiled_in"] = kinfo["kcore_compiled_in"]

    # ── Privileges ───────────────────────────────────────────────────────────
    status["has_root"] = os.geteuid() == 0

    # ── LiME check ───────────────────────────────────────────────────────────
    lime_path = find_lime_module(hint=lime_hint)
    if lime_path is not None:
        status["lime_available"] = True
        status["lime_module_path"] = str(lime_path)

    # Check if we can build LiME from source
    build_reqs = check_lime_build_requirements()
    status["lime_can_build"] = build_reqs["can_build"]

    # ── Linux ISF check (needed for Volatility 3 Linux plugins) ─────────────
    from forensiq.acquisition.linux_isf import (
        check_linux_isf_requirements,
        find_linux_isf,
    )

    release = status["kernel_release"]
    isf_path = find_linux_isf(release)
    if isf_path:
        status["linux_isf_available"] = True
        status["linux_isf_path"] = str(isf_path)
    isf_reqs = check_linux_isf_requirements(release)
    status["linux_isf_can_build"] = isf_reqs["can_build"]

    # ── /proc/kcore existence ────────────────────────────────────────────────
    status["kcore_exists"] = KCORE_PATH.exists()
    if not status["kcore_exists"]:
        if status["kernel_hardened"]:
            status["error"] = (
                "/proc/kcore not found. Your kernel (linux-hardened) disables "
                "CONFIG_PROC_KCORE intentionally.\n"
                "Use LiME instead: sudo forensiq live --lime\n"
                "  Auto-build: sudo forensiq live --build-lime\n"
                "  Manual build: git clone https://github.com/504ensicsLabs/LiME"
            )
        else:
            status["error"] = (
                "/proc/kcore not found. Ensure kernel was compiled with "
                "CONFIG_PROC_KCORE=y and /proc is mounted."
            )
        return status

    # ── /proc/kcore readability ───────────────────────────────────────────────
    try:
        with KCORE_PATH.open("rb") as f:
            hdr = f.read(4)
        status["kcore_readable"] = len(hdr) == 4
    except PermissionError:
        status["kcore_readable"] = False
        status["error"] = (
            "Permission denied reading /proc/kcore. Run forensiq as root: sudo forensiq live"
        )
        return status
    except OSError as exc:
        status["kcore_readable"] = False
        status["error"] = f"Error reading /proc/kcore: {exc}"
        return status

    # ── /proc/kcore size (sparse ELF — st_size == physical address space) ────
    try:
        status["kcore_size_ok"] = KCORE_PATH.stat().st_size >= _KCORE_MIN_BYTES
    except OSError:
        status["kcore_size_ok"] = False

    # ── Final verdict ─────────────────────────────────────────────────────────
    if status["kcore_exists"] and status["kcore_readable"] and status["kcore_size_ok"]:
        status["ready"] = True
        status["error"] = ""
    elif not status["has_root"]:
        status["error"] = "Root privileges required. Run: sudo forensiq live"

    return status


def get_kcore_path() -> Path:
    """Return the /proc/kcore path after validating accessibility.

    Raises:
        LiveMemoryError: If /proc/kcore is not accessible.
    """
    status = check_live_requirements()
    if not status["ready"]:
        raise LiveMemoryError(str(status["error"]))
    return KCORE_PATH
