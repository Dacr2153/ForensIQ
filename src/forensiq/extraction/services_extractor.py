# FILE: src/forensiq/extraction/services_extractor.py
"""Windows services extractor using Volatility 3 windows.svcscan plugin.

Extracts all Windows services and flags suspicious ones:
    - Services running from non-standard paths (Temp, AppData, etc.)
    - Services with missing or obfuscated binary paths
    - Kernel driver services from suspicious paths
    - Services with no display name (often malware)

MITRE ATT&CK:
    T1543.003 — Create or Modify System Process: Windows Service
    T1036.004 — Masquerading: Masquerade Task or Service
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from forensiq.acquisition.volatility_runner import VolatilityRunner
from forensiq.utils.logger import get_logger

log = get_logger(__name__)

# Service binary path fragments that indicate suspicious location
_SUSPICIOUS_SERVICE_PATHS = (
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\",
    "\\users\\",
    "\\public\\",
    "\\downloads\\",
    "\\desktop\\",
    "\\recycler",
    "$recycle.bin",
)


@dataclass
class ServiceEntry:
    """A single Windows service entry from windows.svcscan."""

    order: int
    pid: int
    service_name: str
    display_name: str
    service_type: str
    service_state: str
    binary_path: str

    @property
    def is_suspicious_path(self) -> bool:
        """True if service binary is in a suspicious/user-writable location."""
        if not self.binary_path:
            return True  # No path = suspicious (deleted/obfuscated binary)
        path_lower = self.binary_path.lower()
        return any(s in path_lower for s in _SUSPICIOUS_SERVICE_PATHS)

    @property
    def is_running(self) -> bool:
        """True if the service is currently running."""
        return "running" in self.service_state.lower()

    @property
    def has_no_display_name(self) -> bool:
        """True if the display name is missing or matches the service name exactly."""
        return not self.display_name or self.display_name == self.service_name


class ServicesExtractor:
    """Extracts and analyzes Windows services from windows.svcscan."""

    def __init__(self, runner: VolatilityRunner) -> None:
        self._runner = runner

    def extract(self) -> list[ServiceEntry]:
        """Run windows.svcscan and return all service entries.

        Returns:
            List of ServiceEntry objects (all services, not just suspicious ones).
            Empty list if plugin fails.
        """
        log.info("Extracting services (windows.svcscan)")

        try:
            rows = self._runner.run_plugin("windows.svcscan")
        except Exception as exc:
            log.warning("windows.svcscan failed, skipping", error=str(exc))
            return []

        services: list[ServiceEntry] = []
        for row in rows:
            entry = self._parse_row(row)
            if entry is not None:
                services.append(entry)

        suspicious_count = sum(1 for s in services if s.is_suspicious_path)
        log.info(
            "Services extraction complete",
            total=len(services),
            suspicious_path=suspicious_count,
            running=sum(1 for s in services if s.is_running),
        )
        return services

    def get_suspicious(self, services: list[ServiceEntry]) -> list[ServiceEntry]:
        """Filter to only suspicious service entries."""
        return [s for s in services if s.is_suspicious_path and s.is_running]

    def _parse_row(self, row: dict[str, Any]) -> ServiceEntry | None:
        """Parse a single svcscan row into ServiceEntry."""
        svc_name = str(row.get("ServiceName", row.get("Name", ""))).strip()
        if not svc_name:
            return None

        try:
            order_val = row.get("Order", row.get("Offset", 0))
            order = int(order_val) if order_val else 0
        except (ValueError, TypeError):
            order = 0

        try:
            pid_val = row.get("PID", row.get("Pid", 0))
            pid = int(pid_val) if pid_val and str(pid_val) not in ("N/A", "-", "") else 0
        except (ValueError, TypeError):
            pid = 0

        return ServiceEntry(
            order=order,
            pid=pid,
            service_name=svc_name,
            display_name=str(row.get("DisplayName", "")).strip(),
            service_type=str(row.get("Type", row.get("ServiceType", ""))).strip(),
            service_state=str(row.get("State", row.get("ServiceState", ""))).strip(),
            binary_path=str(row.get("BinaryPath", row.get("Binary", ""))).strip(),
        )
