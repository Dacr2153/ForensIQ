# FILE: src/forensiq/features/heuristics.py
"""Windows process relationship and behavioral heuristics for feature engineering.

Provides:
    - is_system_path(): Checks if executable is in a known Windows system directory
    - parent_child_legit(): Validates parent-child process relationships
    - has_encoded_cmdline(): Detects Base64/hex encoding in command lines

MITRE ATT&CK coverage:
    T1036.005 — Masquerading: Match Legitimate Name or Location
    T1059.001 — Command and Scripting Interpreter: PowerShell
    T1027     — Obfuscated Files or Information
    T1003.001 — OS Credential Dumping: LSASS Memory
"""

from __future__ import annotations

import re
from pathlib import Path

# ─── Known Windows System Directories ────────────────────────────────────────
# Normalized to lowercase Windows paths (backslash normalized to forward slash).
# These are the directories where legitimate Windows system processes run.
_SYSTEM_DIRS: frozenset[str] = frozenset(
    {
        "\\windows\\system32",
        "\\windows\\syswow64",
        "\\windows\\",
        "\\program files\\",
        "\\program files (x86)\\",
        "\\windows\\servicing\\",
        "\\windows\\winsxs\\",
    }
)

# ─── Known Linux System Directories ───────────────────────────────────────────
# Paths where legitimate system processes and daemons run on Linux.
_LINUX_SYSTEM_DIRS: frozenset[str] = frozenset(
    {
        "/usr/bin/",
        "/usr/sbin/",
        "/bin/",
        "/sbin/",
        "/usr/lib/",
        "/usr/lib64/",
        "/usr/libexec/",
        "/usr/share/",  # package data & app bundles (VSCode, Electron, etc.)
        "/lib/",
        "/lib64/",
        "/usr/local/bin/",
        "/usr/local/sbin/",
        "/usr/local/lib/",
        "/usr/lib/systemd/",
        "/lib/systemd/",
        "/opt/",  # third-party app bundles (JetBrains, Slack, Zoom, etc.)
        # Kernel threads have no path — treat them as system
        "[",  # [kworker/...], [kthreadd], etc.
    }
)


def _normalize_windows_path(path: str) -> str:
    """Normalize a Windows path for comparison: lowercase, forward slashes, no drive letter."""
    if not path:
        return ""
    p = path.strip().rstrip("\x00").lower()
    p = p.replace("\\", "/")
    # Remove drive letter (e.g., "c:")
    if len(p) >= 2 and p[1] == ":":
        p = p[2:]
    # Strip Volatility device path prefix: /device/harddiskvolumex/
    import re as _re

    p = _re.sub(r"^/device/[^/]+/", "/", p)
    return p


def is_system_path(image_file_name: str) -> bool:
    """Return True if the executable runs from a known system directory.

    Handles both Windows and Linux paths automatically based on the first
    character of the path (forward slash = Linux, otherwise Windows).

    Args:
        image_file_name: Full executable path from the process PEB / task_struct.

    Returns:
        True if the path is within a known system directory.
        False if path is empty, in a user directory, or in a temp location.
    """
    if not image_file_name:
        return False

    # Linux paths start with '/' or '[' (kernel thread names like [kworker/...])
    if image_file_name.startswith("/") or image_file_name.startswith("["):
        path = image_file_name.lower()
        for sys_dir in _LINUX_SYSTEM_DIRS:
            if path.startswith(sys_dir):
                return True
        return False

    normalized = _normalize_windows_path(image_file_name)
    for sys_dir in _SYSTEM_DIRS:
        sys_dir_normalized = sys_dir.replace("\\", "/")
        if normalized.startswith(sys_dir_normalized):
            return True
    return False


# ─── Known Legitimate Parent-Child Relationships ──────────────────────────────
# Mapping: parent_name → set of legitimate child names
# Names are lowercase, no extension. This is not exhaustive but covers
# the most common Windows process relationships.
# Violations indicate process masquerading (MITRE T1036) or injection.
_LEGITIMATE_PARENT_CHILD: dict[str, frozenset[str]] = {
    "system": frozenset({"smss"}),
    "smss": frozenset({"csrss", "winlogon", "wininit", "smss"}),
    "wininit": frozenset({"services", "lsass", "lsm"}),
    "winlogon": frozenset({"userinit", "dwm", "csrss", "logonui", "mpnotify"}),
    "services": frozenset(
        {
            "svchost",
            "spoolsv",
            "msiexec",
            "dllhost",
            "taskhost",
            "taskhostw",
            "vssvc",
            "wlms",
            "lsm",
        }
    ),
    "svchost": frozenset(
        {
            "dllhost",
            "wermgr",
            "wusa",
            "msiexec",
            "taskhost",
            "taskhostw",
            "cmd",
            "powershell",
            "csc",
            "vbc",
        }
    ),
    "userinit": frozenset({"explorer"}),
    "explorer": frozenset(
        {
            "cmd",
            "powershell",
            "notepad",
            "mspaint",
            "regedit",
            "control",
            "rundll32",
            "msiexec",
            "iexplore",
            "chrome",
            "firefox",
            "msedge",
            "outlook",
            "winword",
            "excel",
            "powerpnt",
            "taskmgr",
            "dxdiag",
            "calc",
            "wmplayer",
            "write",
        }
    ),
    "lsass": frozenset(),  # lsass should NOT spawn children in normal operation
    "csrss": frozenset(),  # csrss should NOT spawn children in normal operation
    "taskhost": frozenset({"cmd", "powershell"}),
    "taskhostw": frozenset({"cmd", "powershell"}),
}

# Processes that should never have children (spawning children is always suspicious)
_NO_CHILD_PROCESSES: frozenset[str] = frozenset({"lsass", "csrss", "lsm"})


def _get_process_stem(name: str) -> str:
    """Return lowercase name without extension."""

    if not name:
        return ""
    stem = Path(name.lower().strip()).stem
    return stem or name.lower().strip()


def parent_child_legit(parent_name: str, child_name: str) -> bool:
    """Return True if the parent-child process relationship is legitimate.

    Uses a whitelist of known Windows process relationships.
    Unknown parent-child pairs are returned as True (benefit of the doubt)
    to minimize false positives for third-party software.

    Strict enforcement is applied only for LSASS, CSRSS, and other
    processes that should NEVER spawn children in normal operation.

    Args:
        parent_name: Image name of the parent process.
        child_name: Image name of the child process being evaluated.

    Returns:
        True if the relationship is normal or unknown.
        False if the relationship is a known violation.
    """
    if not parent_name or not child_name:
        return True  # Cannot evaluate — no data

    parent_stem = _get_process_stem(parent_name)
    child_stem = _get_process_stem(child_name)

    # Strict check: processes that must not have children
    if parent_stem in _NO_CHILD_PROCESSES:
        return False

    # Check against known legitimate relationships
    allowed_children = _LEGITIMATE_PARENT_CHILD.get(parent_stem)
    if allowed_children is None:
        # Unknown parent — assume legitimate (reduces false positives for 3rd-party apps)
        return True

    # If we have a defined whitelist but the child is not in it,
    # only flag if the child is a clearly dangerous process name
    dangerous_children = frozenset({"mimikatz", "procdump", "wce", "pwdump", "fgdump"})
    if child_stem in dangerous_children:
        return False

    return child_stem in allowed_children


# ─── Command-Line Encoding Detection ──────────────────────────────────────────
# PowerShell's -EncodedCommand flag takes Base64-encoded payloads.
# Malware uses this extensively to evade signature detection.
# MITRE T1059.001, T1027

_BASE64_LONG_PATTERN = re.compile(
    # Base64 string of 30+ characters (long enough to be a real payload, not just a short string)
    r"[A-Za-z0-9+/]{30,}={0,2}",
    re.IGNORECASE,
)

_POWERSHELL_ENCODED_PATTERN = re.compile(
    # PowerShell -EncodedCommand or -enc short form
    r"(?i)(?:powershell|pwsh).*?-(?:EncodedCommand|enc|e)\s+[A-Za-z0-9+/=]{10,}",
    re.IGNORECASE,
)

_HEX_PAYLOAD_PATTERN = re.compile(
    # Long hex strings (16+ hex chars) — common in shellcode loaders.
    # Includes optional 0x prefix; bare hex is also flagged because Windows
    # malware uses `cmd.exe /c echo 4d5a... > file` to reconstruct PE files.
    # NOTE: On Linux, this may match SHA-256 hashes/git commit hashes in cmdlines;
    # callers should apply is_linux context before raising high-severity alerts.
    r"(?:0x)?[0-9a-fA-F]{16,}",
)

_WSCRIPT_EVAL_PATTERN = re.compile(
    # eval/execute with string content — VBScript/JScript obfuscation
    r"(?i)(?:eval|execute|wscript\.shell|createobject)\s*\(",
)


def has_encoded_cmdline(cmdline: str | None) -> bool:
    """Return True if the command line contains encoded or obfuscated content.

    Detects:
        1. PowerShell -EncodedCommand flag with Base64 payload
        2. Long standalone Base64 strings (50+ chars)
        3. Long hex strings (potential shellcode loaders)
        4. WScript.Shell/eval obfuscation patterns

    Args:
        cmdline: Command line string from PEB, or None if not available.

    Returns:
        True if encoding/obfuscation is detected. False if None or clean.
    """
    if not cmdline:
        return False

    if _POWERSHELL_ENCODED_PATTERN.search(cmdline):
        return True
    if _BASE64_LONG_PATTERN.search(cmdline):
        return True
    if _HEX_PAYLOAD_PATTERN.search(cmdline):
        return True
    if _WSCRIPT_EVAL_PATTERN.search(cmdline):
        return True

    return False
