# FILE: src/forensiq/cache/__init__.py
"""ForensIQ caching layer.

Provides two levels of caching:

1. PluginCache  — per-plugin Volatility output, keyed by dump SHA-256.
   Stored at ~/.forensiq/cache/{sha256}/{plugin_name}.json.
   Eliminates the need to re-run Volatility on the same dump file.
   Savings: 60-80% of total analysis time on repeated runs.

2. AnalysisCache — full analysis results keyed by dump SHA-256.
   Checked at pipeline start via ForensiqDatabase.
   If a previous analysis exists for the same dump, the user is asked
   whether to use the cached result or re-analyze.
"""
