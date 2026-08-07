# FILE: src/forensiq/integrations/__init__.py
"""External threat intelligence integrations.

Available:
    - MalwareBazaarClient: Free, no API key required
    - VirusTotalClient: Requires FORENSIQ_VT_API_KEY in environment
"""

from forensiq.integrations.malwarebazaar import MalwareBazaarClient
from forensiq.integrations.virustotal import VirusTotalClient

__all__ = ["MalwareBazaarClient", "VirusTotalClient"]
