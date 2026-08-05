# FILE: src/forensiq/models/network.py
"""Pydantic v2 models for network connection artifacts from Volatility 3.

Uses windows.netscan plugin output to detect:
    - External connections (to non-RFC1918 IPs)
    - Connections on suspicious/known-malware ports
    - C2 callback patterns

Models:
    ConnectionState — Enum of TCP connection states
    NetworkConnection — Single TCP/UDP connection extracted from a memory dump
"""

from __future__ import annotations

import ipaddress
from enum import StrEnum

from pydantic import BaseModel, Field, computed_field, field_validator

# ─── Known-Malicious / Suspicious Port List ───────────────────────────────────
# These ports are commonly used in C2 frameworks, RATs, and reverse shells.
# Not exhaustive — high-entropy ports and known-good ports are handled by ML.
_SUSPICIOUS_PORTS: frozenset[int] = frozenset(
    {
        # Metasploit defaults
        4444,
        4445,
        # Common reverse shell ports
        1337,
        9001,
        9002,
        9003,
        # Elite hacker aesthetic (used in many RATs)
        31337,
        # IRC C2 (botnet legacy)
        6666,
        6667,
        6668,
        6669,
        # Common backdoor ports
        8888,
        8443,
        # High ports used by RATs
        65535,
        65000,
        60001,
        # Cobalt Strike default beacon
        50050,
        # Netcat/ncat default
        1234,
    }
)


# ─── Private Network Ranges (RFC 1918 + loopback + link-local) ───────────────
_PRIVATE_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),  # Link-local
    ipaddress.IPv4Network("0.0.0.0/8"),  # Unspecified (UDP listen)
    ipaddress.IPv6Network("::1/128"),  # IPv6 loopback
    ipaddress.IPv6Network("fc00::/7"),  # IPv6 private (ULA)
    ipaddress.IPv6Network("fe80::/10"),  # IPv6 link-local
)


def _is_private_ip(addr: str) -> bool:
    """Return True if the address is in a private or special-purpose range."""
    if not addr or addr in ("", "*", "-", "N/A"):
        return True  # Unresolved addresses are treated as non-external
    try:
        ip = ipaddress.ip_address(addr)
        return any(ip in network for network in _PRIVATE_NETWORKS)
    except ValueError:
        # Hostname strings (e.g., "DESKTOP-XYZ") are treated as non-external
        return True


class ConnectionState(StrEnum):
    """TCP connection states as reported by Volatility 3 windows.netscan plugin."""

    ESTABLISHED = "ESTABLISHED"
    CLOSE_WAIT = "CLOSE_WAIT"
    TIME_WAIT = "TIME_WAIT"
    FIN_WAIT1 = "FIN_WAIT1"
    FIN_WAIT2 = "FIN_WAIT2"
    LISTEN = "LISTEN"
    SYN_SENT = "SYN_SENT"
    SYN_RECV = "SYN_RECV"
    LAST_ACK = "LAST_ACK"
    CLOSED = "CLOSED"
    CLOSING = "CLOSING"
    # UDP "connections" and unknown states
    UNKNOWN = "UNKNOWN"


def _parse_connection_state(state: str) -> str:
    """Normalize state string from Volatility output."""
    if not state or state in ("-", "N/A", ""):
        return ConnectionState.UNKNOWN
    upper = state.upper().strip()
    # Volatility sometimes outputs just the state code
    state_map = {
        "ESTABLISHED": ConnectionState.ESTABLISHED,
        "CLOSE_WAIT": ConnectionState.CLOSE_WAIT,
        "CLOSE WAIT": ConnectionState.CLOSE_WAIT,
        "TIME_WAIT": ConnectionState.TIME_WAIT,
        "TIME WAIT": ConnectionState.TIME_WAIT,
        "FIN_WAIT1": ConnectionState.FIN_WAIT1,
        "FIN_WAIT2": ConnectionState.FIN_WAIT2,
        "LISTEN": ConnectionState.LISTEN,
        "SYN_SENT": ConnectionState.SYN_SENT,
        "SYN_RECV": ConnectionState.SYN_RECV,
        "LAST_ACK": ConnectionState.LAST_ACK,
        "CLOSED": ConnectionState.CLOSED,
        "CLOSING": ConnectionState.CLOSING,
    }
    return state_map.get(upper, ConnectionState.UNKNOWN)


class NetworkConnection(BaseModel):
    """A single network connection or socket entry from windows.netscan.

    Attributes map directly to Volatility 3 netscan output columns.
    All addresses are stored as strings (IPv4 or IPv6 dotted notation).
    Ports are stored as integers (-1 if not applicable, e.g., UDP sockets).

    Computed fields:
        is_external: True if the remote address is a non-RFC1918 routable IP.
        is_suspicious_port: True if the local or remote port is in the known-bad list.
    """

    pid: int = Field(..., description="PID of the owning process", ge=0)
    proto: str = Field(
        ...,
        description="Protocol string: 'TCPv4', 'TCPv6', 'UDPv4', 'UDPv6'",
    )
    local_addr: str = Field(
        default="",
        description="Local IP address (dotted notation). Empty string for unresolved.",
    )
    local_port: int = Field(
        default=-1,
        description="Local port number. -1 if not applicable (UDP listening socket).",
        ge=-1,
    )
    remote_addr: str = Field(
        default="",
        description="Remote IP address. Empty string for listening sockets.",
    )
    remote_port: int = Field(
        default=-1,
        description="Remote port number. -1 for listening sockets.",
        ge=-1,
    )
    state: str = Field(
        default=ConnectionState.UNKNOWN,
        description="TCP connection state. 'UNKNOWN' for UDP or unresolved state.",
    )

    @field_validator("proto")
    @classmethod
    def normalize_proto(cls, v: str) -> str:
        """Normalize protocol string to uppercase."""
        return v.upper().strip()

    @field_validator("state", mode="before")
    @classmethod
    def normalize_state(cls, v: str | None) -> str:
        """Parse and normalize connection state string from Volatility output."""
        if v is None:
            return ConnectionState.UNKNOWN
        return _parse_connection_state(str(v))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_external(self) -> bool:
        """True if the remote address is a globally routable (non-RFC1918) IP.

        External connections in non-browser processes are a strong IOC.
        """
        return not _is_private_ip(self.remote_addr)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_suspicious_port(self) -> bool:
        """True if the local or remote port matches a known-malicious port list.

        Checking both local and remote ports catches both bind-based backdoors
        (local port) and connect-based C2 callbacks (remote port).
        """
        if self.local_port in _SUSPICIOUS_PORTS:
            return True
        if self.remote_port in _SUSPICIOUS_PORTS:
            return True
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_active(self) -> bool:
        """True if the connection is ESTABLISHED or LISTEN (active socket)."""
        return self.state in (ConnectionState.ESTABLISHED, ConnectionState.LISTEN)

    def __repr__(self) -> str:
        return (
            f"NetworkConnection("
            f"pid={self.pid}, "
            f"proto={self.proto}, "
            f"{self.local_addr}:{self.local_port} → "
            f"{self.remote_addr}:{self.remote_port}, "
            f"state={self.state})"
        )
