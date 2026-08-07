# FILE: src/forensiq/db/__init__.py
"""ForensIQ SQLite Historical Database.

Stores analysis results persistently for:
    - Trend analysis across multiple dumps
    - IOC caching (VirusTotal/MalwareBazaar lookups)
    - Cross-dump comparison (new process vs. baseline)
    - Generated YARA rules linked to each analysis

Usage:
    from forensiq.db.manager import ForensiqDatabase

    async with ForensiqDatabase() as db:
        await db.save_analysis(report)
        findings = await db.get_recent_findings(days=7)
"""

from forensiq.db.manager import ForensiqDatabase

__all__ = ["ForensiqDatabase"]
