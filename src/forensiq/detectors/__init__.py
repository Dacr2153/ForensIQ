# FILE: src/forensiq/detectors/__init__.py
"""ForensIQ Detector Plugin System.

Each detector is an independent module that implements the BaseDetector interface.
Detectors are discovered and run by the DetectorRegistry.

Adding a new detector:
    1. Create forensiq/detectors/my_detector.py
    2. Subclass BaseDetector and implement detect()
    3. Register an instance with DetectorRegistry.register()

Available detectors:
    - ProcessAnomalyDetector: Threshold adaptive, masquerading, parent-child
    - CrossViewDetector: psscan vs pslist DKOM rootkit detection
    - HandlesMutexDetector: Malicious mutex / registry handle detection
    - ServicesScanDetector: windows.svcscan malicious service detection
    - MalfindStringsDetector: Strings extraction + IOC parsing
    - PEHeaderDetector: PE analysis of injected regions
    - ThreatIntelDetector: VirusTotal / MalwareBazaar hash lookup
"""

from forensiq.detectors.base import BaseDetector, DetectorResult, FindingSeverity
from forensiq.detectors.cross_view import CrossViewDetector
from forensiq.detectors.handles_mutex import HandlesMutexDetector
from forensiq.detectors.malfind_strings import MalfindStringsDetector
from forensiq.detectors.pe_header import PEHeaderDetector
from forensiq.detectors.process_anomaly import ProcessAnomalyDetector
from forensiq.detectors.registry import DetectorRegistry
from forensiq.detectors.services_scan import ServicesScanDetector
from forensiq.detectors.threat_intel import ThreatIntelDetector

__all__ = [
    "BaseDetector",
    "CrossViewDetector",
    "DetectorRegistry",
    "DetectorResult",
    "FindingSeverity",
    "HandlesMutexDetector",
    "MalfindStringsDetector",
    "PEHeaderDetector",
    "ProcessAnomalyDetector",
    "ServicesScanDetector",
    "ThreatIntelDetector",
]
