# FILE: src/forensiq/extraction/network_extractor.py
"""Network connection extraction from Volatility 3 windows.netscan plugin.

windows.netscan scans the Windows kernel pool for TCPT_OBJECT and
TcpEndpoint structures, recovering network connections even if they
have been removed from the active connection list (potential DKOM evasion).

Usage:
    from forensiq.extraction.network_extractor import NetworkExtractor
    from forensiq.acquisition.volatility_runner import VolatilityRunner

    runner = VolatilityRunner(dump_path=Path("/dumps/memory.raw"))
    extractor = NetworkExtractor(runner)
    connections = extractor.extract()
    # connections: dict[int, list[NetworkConnection]] keyed by PID
"""

from __future__ import annotations

import os
import re
import socket
import struct
from pathlib import Path
from typing import Any, ClassVar

from forensiq.acquisition.volatility_runner import VolatilityRunner
from forensiq.extraction._utils import _PID_COLS, _find_col
from forensiq.models.network import NetworkConnection
from forensiq.utils.logger import get_logger

log = get_logger(__name__)

# ─── Column name mappings ──────────────────────────────────────────────────────
_PROTO_COLS = ("Proto", "Protocol", "proto")
# Linux sockstat: "Source Addr" / "Destination Addr"
_LOCAL_ADDR_COLS = ("LocalAddr", "local_addr", "LocalAddress", "Source Addr")
_LOCAL_PORT_COLS = ("LocalPort", "local_port", "Source Port")
_REMOTE_ADDR_COLS = (
    "ForeignAddr",
    "RemoteAddr",
    "remote_addr",
    "ForeignAddress",
    "RemoteAddress",
    "Destination Addr",
)
_REMOTE_PORT_COLS = ("ForeignPort", "RemotePort", "remote_port", "Destination Port")
_STATE_COLS = ("State", "state")


def _parse_port(val: Any) -> int:
    """Parse a port number from Volatility output. Returns -1 if not applicable."""
    if val is None:
        return -1
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        val = val.strip()
        if not val or val in ("-", "N/A", "*", "0"):
            return -1
        try:
            return int(val)
        except ValueError:
            return -1
    return -1


def _parse_addr(val: Any) -> str:
    """Parse an IP address from Volatility output."""
    if val is None:
        return ""
    if isinstance(val, str):
        cleaned = val.strip()
        if cleaned in ("-", "N/A", "*", "0.0.0.0"):  # noqa: S104
            return cleaned if cleaned == "0.0.0.0" else ""  # noqa: S104
        return cleaned
    return str(val)


class NetworkExtractor:
    """Extracts network connection artifacts from windows.netscan output.

    Args:
        runner: Configured VolatilityRunner for the target dump.
    """

    # /proc/net TCP/UDP state codes
    _TCP_STATES: ClassVar[dict[int, str]] = {
        1: "ESTABLISHED",
        2: "SYN_SENT",
        3: "SYN_RECV",
        4: "FIN_WAIT1",
        5: "FIN_WAIT2",
        6: "TIME_WAIT",
        7: "CLOSE",
        8: "CLOSE_WAIT",
        9: "LAST_ACK",
        10: "LISTEN",
        11: "CLOSING",
        12: "NEW_SYN_RECV",
    }
    _SOCKET_RE = re.compile(r"socket:\[(\d+)\]")

    def _build_inode_to_pid(self) -> dict[int, int]:
        """Map socket inode numbers to PIDs via /proc/PID/fd symlinks."""
        inode_to_pid: dict[int, int] = {}
        try:
            for entry in Path("/proc").iterdir():
                if not entry.name.isdigit():
                    continue
                fd_dir = entry / "fd"
                try:
                    for fd_path in fd_dir.iterdir():
                        try:
                            target = os.readlink(fd_path)  # noqa: PTH115
                            m = self._SOCKET_RE.match(target)
                            if m:
                                inode_to_pid[int(m.group(1))] = int(entry.name)
                        except OSError:
                            pass
                except OSError:
                    pass
        except OSError:
            pass
        return inode_to_pid

    def _parse_proc_net(
        self,
        path: Path,
        proto: str,
        is_ipv6: bool,
        inode_to_pid: dict[int, int],
    ) -> list[NetworkConnection]:
        """Parse a /proc/net/{tcp,tcp6,udp,udp6} table into NetworkConnections."""
        connections: list[NetworkConnection] = []
        try:
            lines = path.read_text().splitlines()[1:]  # skip header
        except OSError:
            return connections

        for line in lines:
            parts = line.split()
            if len(parts) < 10:
                continue
            try:
                local_hex, rem_hex = parts[1], parts[2]
                state_int = int(parts[3], 16)
                inode = int(parts[9])
            except (IndexError, ValueError):
                continue

            pid = inode_to_pid.get(inode, 0)
            state = self._TCP_STATES.get(state_int, f"STATE_{state_int}")

            def _hex_to_addr(hex_str: str) -> tuple[str, int]:
                addr_hex, port_hex = hex_str.split(":")
                port = int(port_hex, 16)
                if is_ipv6:
                    # 32 hex chars = 16 bytes; stored as 4 little-endian 32-bit words
                    raw = b"".join(
                        struct.pack("<I", int(addr_hex[i : i + 8], 16)) for i in range(0, 32, 8)
                    )
                    addr = socket.inet_ntop(socket.AF_INET6, raw)
                else:
                    # 8 hex chars = 4 bytes little-endian
                    raw = struct.pack("<I", int(addr_hex, 16))
                    addr = socket.inet_ntoa(raw)
                return addr, port

            try:
                local_addr, local_port = _hex_to_addr(local_hex)
                rem_addr, rem_port = _hex_to_addr(rem_hex)
            except (OSError, ValueError, struct.error):
                continue

            connections.append(
                NetworkConnection(
                    pid=pid,
                    proto=proto,
                    local_addr=local_addr,
                    local_port=local_port,
                    remote_addr=rem_addr,
                    remote_port=rem_port,
                    state=state,
                )
            )
        return connections

    def _connections_from_proc_net(self) -> dict[int, list[NetworkConnection]]:
        """Read network connections from /proc/net as fallback for linux.sockstat."""
        if not Path("/proc/net").exists():
            return {}

        inode_to_pid = self._build_inode_to_pid()
        connections_by_pid: dict[int, list[NetworkConnection]] = {}

        for path, proto, is_ipv6 in (
            (Path("/proc/net/tcp"), "TCPv4", False),
            (Path("/proc/net/tcp6"), "TCPv6", True),
            (Path("/proc/net/udp"), "UDPv4", False),
            (Path("/proc/net/udp6"), "UDPv6", True),
        ):
            for conn in self._parse_proc_net(path, proto, is_ipv6, inode_to_pid):
                connections_by_pid.setdefault(conn.pid, []).append(conn)

        total = sum(len(v) for v in connections_by_pid.values())
        if total:
            log.info(
                "Network connections read from /proc/net (linux.sockstat fallback)",
                total=total,
                pids=len(connections_by_pid),
            )
        return connections_by_pid

    def __init__(self, runner: VolatilityRunner) -> None:
        self._runner = runner

    def _row_to_connection(self, row: dict[str, Any]) -> NetworkConnection | None:
        """Convert a single netscan row to a NetworkConnection.

        Args:
            row: A row dict from windows.netscan JSON output.

        Returns:
            NetworkConnection if parseable, None if row is malformed.
        """
        pid_raw = _find_col(row, _PID_COLS)
        proto_raw = _find_col(row, _PROTO_COLS)

        if pid_raw is None or proto_raw is None:
            return None

        try:
            pid = int(pid_raw) if pid_raw is not None else 0
        except (ValueError, TypeError):
            return None

        proto = str(proto_raw).strip().upper()
        if not proto:
            return None

        return NetworkConnection(
            pid=pid,
            proto=proto,
            local_addr=_parse_addr(_find_col(row, _LOCAL_ADDR_COLS)),
            local_port=_parse_port(_find_col(row, _LOCAL_PORT_COLS)),
            remote_addr=_parse_addr(_find_col(row, _REMOTE_ADDR_COLS)),
            remote_port=_parse_port(_find_col(row, _REMOTE_PORT_COLS)),
            state=_find_col(row, _STATE_COLS) or "UNKNOWN",
        )

    def extract(self) -> dict[int, list[NetworkConnection]]:
        """Run windows.netscan and return connections grouped by PID.

        Returns:
            Dict mapping PID → list of NetworkConnection objects.
            Processes with no connections are absent from the dict.
            Empty dict if netscan produces no output (not an error — normal
            for older dumps or dumps taken at an idle moment).
        """
        log.info("Extracting network connections")
        # Linux: linux.sockstat  Windows: windows.netscan
        plugin = "linux.sockstat" if self._runner.is_linux else "windows.netscan"
        try:
            rows = self._runner.run_plugin(plugin)
        except Exception as exc:
            log.warning(
                f"{plugin} failed, continuing without network data",
                error=str(exc),
            )
            return {}

        connections_by_pid: dict[int, list[NetworkConnection]] = {}
        skipped = 0

        for row in rows:
            conn = self._row_to_connection(row)
            if conn is None:
                skipped += 1
                continue
            connections_by_pid.setdefault(conn.pid, []).append(conn)

        total = sum(len(c) for c in connections_by_pid.values())
        log.info(
            "Network connections extracted",
            total=total,
            pids_with_connections=len(connections_by_pid),
            skipped=skipped,
        )
        return connections_by_pid

    async def extract_async(self) -> dict[int, list[NetworkConnection]]:
        """Async variant: run linux.sockstat/windows.netscan via asyncio subprocess."""
        from forensiq.models.network import NetworkConnection  # noqa: F401 — type alias

        log.info("Extracting network connections (async)")
        plugin = "linux.sockstat" if self._runner.is_linux else "windows.netscan"
        try:
            rows = await self._runner.run_plugin_async(plugin)
        except Exception as exc:
            log.warning(f"{plugin} async failed, continuing", error=str(exc))
            rows = []

        connections_by_pid: dict[int, list[NetworkConnection]] = {}
        skipped = 0
        for row in rows:
            conn = self._row_to_connection(row)
            if conn is None:
                skipped += 1
                continue
            connections_by_pid.setdefault(conn.pid, []).append(conn)

        # If the Volatility plugin failed and we're on a live Linux system,
        # fall back to /proc/net which provides the same data directly from
        # the kernel's network subsystem.
        if not connections_by_pid and self._runner.is_linux:
            connections_by_pid = self._connections_from_proc_net()

        total = sum(len(c) for c in connections_by_pid.values())
        log.info(
            "Network connections extracted (async)",
            total=total,
            pids_with_connections=len(connections_by_pid),
        )
        return connections_by_pid
