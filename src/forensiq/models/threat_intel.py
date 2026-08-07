# FILE: src/forensiq/models/threat_intel.py
"""Shared threat-intelligence result model.

Single source of truth for the hash-lookup result returned by all threat
intelligence providers (VirusTotal, MalwareBazaar, ...). Providers subclass
or populate this model; consumers (detectors, cache) depend only on this
module, never on a specific integration package.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ThreatIntelResult:
    """Result from a threat intelligence hash lookup.

    Attributes:
        hash_value: The queried hash (MD5/SHA-1/SHA-256, lowercase hex).
        hash_type: "md5", "sha1", or "sha256".
        source: Provider name ("virustotal", "malwarebazaar", ...).
        is_malicious: True when the provider flags the hash as malicious.
        verdict: "malicious", "clean", "unknown", "unavailable", "error", or
            "rate_limited".
        malware_name: Primary malware name/signature, if known.
        malware_family: Malware family, if known.
        tags: Provider tags associated with the sample.
        first_seen: First-seen timestamp (ISO-8601 when available).
        raw_response: The provider's raw response payload.
    """

    hash_value: str
    hash_type: str
    source: str
    is_malicious: bool
    verdict: str
    malware_name: str = ""
    malware_family: str = ""
    tags: list[str] = field(default_factory=list)
    first_seen: str = ""
    raw_response: dict[str, Any] = field(default_factory=dict)
