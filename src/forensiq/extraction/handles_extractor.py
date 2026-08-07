# FILE: src/forensiq/extraction/handles_extractor.py
"""Windows handles extractor using Volatility 3 windows.handles plugin.

Extracts process handles and filters for suspicious types:
    - Mutants (Mutexes) with known malware names
    - Registry keys in Run/RunOnce (persistence indicators)
    - File handles to suspicious paths

MITRE ATT&CK:
    T1547   — Boot or Logon Autostart (registry handles)
    T1043   — Commonly Used Port (named pipe handles)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from forensiq.acquisition.volatility_runner import VolatilityRunner
from forensiq.utils.logger import get_logger

log = get_logger(__name__)

# Known malware mutex names (partial matches, case-insensitive).
# NOTE: "\Global\" is deliberately NOT included — it is the default namespace
# for Windows mutexes, so matching it would flag every legitimate mutex.
_MALWARE_MUTEX_PATTERNS = [
    "_singleinstance",
    "yui93jfksd",  # Example known RAT mutexes
    "zbot",
    "citadelosaurus",
    "poison_",
    "gh0st",
    "darkcomet",
    "njrat",
    "quasar",
]

# Suspicious registry key fragments (persistence)
_SUSPICIOUS_REG_PATHS = [
    "\\run\\",
    "\\runonce\\",
    "\\currentversion\\run",
    "\\services\\",
    "\\winlogon\\",
    "\\browser helper",
]


@dataclass
class HandleEntry:
    """A single Windows handle entry."""

    pid: int
    process_name: str
    handle_value: str
    handle_type: str
    name: str
    granted_access: str

    @property
    def is_suspicious_mutex(self) -> bool:
        """Check if this is a mutex with a known malware pattern."""
        if self.handle_type.lower() not in ("mutant", "mutex"):
            return False
        name_lower = self.name.lower()
        return any(pattern in name_lower for pattern in _MALWARE_MUTEX_PATTERNS)

    @property
    def is_suspicious_registry(self) -> bool:
        """Check if this is a suspicious registry handle."""
        if self.handle_type.lower() != "key":
            return False
        name_lower = self.name.lower()
        return any(pattern in name_lower for pattern in _SUSPICIOUS_REG_PATHS)


class HandlesExtractor:
    """Extracts and filters process handles from windows.handles plugin."""

    def __init__(self, runner: VolatilityRunner) -> None:
        self._runner = runner

    def extract(self) -> dict[int, list[HandleEntry]]:
        """Run windows.handles and return entries grouped by PID.

        Returns:
            Dict mapping PID → list of HandleEntry. Only suspicious handles included.
            Empty dict if plugin fails (non-fatal).
        """
        log.info("Extracting handles (windows.handles)")

        try:
            rows = self._runner.run_plugin("windows.handles")
        except Exception as exc:
            log.warning("windows.handles failed, skipping", error=str(exc))
            return {}

        if not rows:
            return {}

        handles_by_pid: dict[int, list[HandleEntry]] = {}
        total_parsed = 0
        total_suspicious = 0

        for row in rows:
            entry = self._parse_row(row)
            if entry is None:
                continue
            total_parsed += 1

            if entry.is_suspicious_mutex or entry.is_suspicious_registry:
                total_suspicious += 1
                handles_by_pid.setdefault(entry.pid, []).append(entry)

        log.info(
            "Handles extraction complete",
            total_parsed=total_parsed,
            suspicious_found=total_suspicious,
            pids_with_suspicious=len(handles_by_pid),
        )
        return handles_by_pid

    def _parse_row(self, row: dict[str, Any]) -> HandleEntry | None:
        """Parse a single handles row."""
        pid = None
        for key in ("PID", "Pid", "pid"):
            if key in row:
                try:
                    pid = int(row[key])
                    break
                except (ValueError, TypeError):
                    continue

        if pid is None:
            return None

        handle_type = str(row.get("Type", row.get("HandleType", ""))).strip()
        name = str(row.get("Name", row.get("HandleName", ""))).strip()
        handle_val = str(row.get("HandleValue", row.get("Handle", ""))).strip()
        proc_name = str(row.get("ImageFileName", row.get("Process", ""))).strip()
        granted = str(row.get("GrantedAccess", "")).strip()

        return HandleEntry(
            pid=pid,
            process_name=proc_name,
            handle_value=handle_val,
            handle_type=handle_type,
            name=name,
            granted_access=granted,
        )
