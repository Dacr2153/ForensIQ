# FILE: src/forensiq/detectors/__init__.py
"""ForensIQ Detector Plugin System.

Each detector is an independent module that implements the BaseDetector interface.
Detectors are discovered and run by the DetectorRegistry.

Adding a new detector:
    1. Create forensiq/detectors/my_detector.py
    2. Subclass BaseDetector and implement detect()
    3. Register with @register_detector decorator

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
from forensiq.detectors.registry import DetectorRegistry

__all__ = [
    "BaseDetector",
    "DetectorRegistry",
    "DetectorResult",
    "FindingSeverity",
]
