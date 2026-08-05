# FILE: src/forensiq/__init__.py
"""ForensIQ — Memory Forensics & Threat Hunting Platform.

A professional-grade DFIR tool for detecting fileless malware in Windows
memory dumps using:
    - Volatility 3 for artifact extraction
    - XGBoost for ML-based process classification
    - Ollama (auto-detected local model) for YARA rule generation
    - Jinja2 for HTML forensic reports

Usage:
    forensiq analyze /path/to/memory.dump
    forensiq train /path/to/dataset.csv
    forensiq check

For authorized forensic analysis only.
"""

__version__ = "1.0.0"
__author__ = "ForensIQ Team"
__license__ = "MIT"

# Expose version for `python -m forensiq --version`
__all__ = ["__version__"]
