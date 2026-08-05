# FILE: src/forensiq/detectors/process_anomaly.py
"""Process Anomaly Detector — adaptive threshold + masquerading detection.

Detects:
    - Suspicious parent-child relationships (T1036.005)
    - Process name masquerading (T1036)
    - System processes running from wrong paths (T1036.005)
    - Suspicious execution from temp/user dirs (T1204.002)
    - Processes with high threat score using adaptive thresholds by type

Adaptive thresholds:
    System critical processes (lsass, csrss, smss, etc.) use a higher
    detection threshold (0.92) because they are always "anomalous" by
    ML metrics but almost never actually malicious. User processes use
    the default threshold (0.65).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from forensiq.detectors.base import BaseDetector, DetectorResult, FindingSeverity

if TYPE_CHECKING:
    from forensiq.extraction.orchestrator import ExtractionResult
    from forensiq.models.features import ProcessFeatureVector

# Processes that legitimately run as children of specific parents
# Format: child_name -> set of valid parent names
VALID_PARENT_MAP: dict[str, set[str]] = {
    "smss.exe": {"system", ""},
    "csrss.exe": {"smss.exe"},
    "wininit.exe": {"smss.exe"},
    "winlogon.exe": {"smss.exe"},
    "services.exe": {"wininit.exe"},
    "lsass.exe": {"wininit.exe"},
    "lsm.exe": {"wininit.exe"},
    "svchost.exe": {"services.exe"},
    "taskhost.exe": {"services.exe"},
    "spoolsv.exe": {"services.exe"},
    "explorer.exe": {"userinit.exe", ""},
}

# System processes that should ONLY run from %SystemRoot%\System32\
SYSTEM_ONLY_PROCESSES: set[str] = {
    "lsass.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "smss.exe",
    "services.exe",
    "lsm.exe",
}

# Adaptive thresholds: critical system processes need higher score before
# they are flagged as malicious (they have unusual ML features by default)
ADAPTIVE_THRESHOLDS: dict[str, float] = {
    "system": 0.97,
    "smss.exe": 0.95,
    "csrss.exe": 0.95,
    "wininit.exe": 0.95,
    "lsass.exe": 0.92,
    "services.exe": 0.92,
    "winlogon.exe": 0.90,
    "lsm.exe": 0.92,
    "svchost.exe": 0.85,
    "spoolsv.exe": 0.80,
    "explorer.exe": 0.75,
}

# Suspicious execution paths (lowercase substrings)
SUSPICIOUS_PATH_FRAGMENTS: list[str] = [
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\",
    "\\downloads\\",
    "\\desktop\\",
    "\\public\\",
    "\\recycle",
    "\\users\\",
    "/tmp/",  # noqa: S108
    "/var/tmp/",  # noqa: S108
]

# Linux processes that legitimately create anonymous RWX memory pages via JIT engines
# or shader compilation. These are EXCLUDED from the compromised-system-binary check
# because their RWX pages are a normal side-effect of dynamic code generation.
_LINUX_JIT_PROCESSES: frozenset[str] = frozenset(
    {
        # Electron-based editors / apps
        "code",
        "code-oss",
        "electron",
        # Chromium-based browsers
        "chrome",
        "chromium",
        "chromium-browser",
        "google-chrome-stable",
        "brave-browser",
        "opera",
        # Firefox (SpiderMonkey JIT)
        "firefox",
        "firefox-esr",
        "firefox-bin",
        # JavaScript / WASM runtimes
        "node",
        "nodejs",
        "deno",
        "bun",
        # JVM-based
        "java",
        "javac",
        # Dynamic languages with JIT (PyPy, Numba, etc.)
        "python",
        "python3",
        "pypy",
        "pypy3",
        # Other JIT runtimes
        "luajit",
        "mono",
        "dotnet",
        # Wayland/X11 compositors and GPU processes (Mesa shader compilation)
        "kwin_wayland",
        "kwin_x11",
        "mutter",
        "sway",
        "Xwayland",
        "Xorg",
    }
)


class ProcessAnomalyDetector(BaseDetector):
    """Detect process anomalies using heuristic rules and adaptive thresholds.

    This detector runs heuristic checks on all processes, independent of
    the ML threat score. It catches masquerading and structural anomalies
    that the XGBoost model may miss.
    """

    name = "process_anomaly"
    description = (
        "Detects process masquerading, wrong-parent spawning, "
        "suspicious execution paths, and applies adaptive thresholds "
        "for critical system processes."
    )

    def detect(
        self,
        extraction: ExtractionResult,
        vectors: list[ProcessFeatureVector],
    ) -> list[DetectorResult]:
        findings: list[DetectorResult] = []

        if extraction.process_tree is None:
            return findings

        # Detect OS type from dump extension (mirrors analysis_pipeline logic)
        is_linux = getattr(extraction, "is_linux", False)

        # Build PID→name lookup for parent checks
        pid_to_name: dict[int, str] = {
            pid: proc.name.lower() for pid, proc in extraction.process_tree.flat_map.items()
        }

        for v in vectors:
            if is_linux:
                # Linux-specific heuristic checks (no ML classifier output available)
                findings.extend(self._check_linux_rwx_memory(v))
                findings.extend(self._check_linux_compromised_binary(v))
                findings.extend(self._check_linux_suspicious_path(v, extraction))
                findings.extend(self._check_linux_suspicious_dll(v, extraction))
            else:
                # Windows-specific checks
                findings.extend(self._check_adaptive_threshold(v))
                findings.extend(self._check_parent_relationship(v, pid_to_name))
                findings.extend(self._check_system_process_path(v))
                findings.extend(self._check_suspicious_path(v))

        return findings

    # ─── Linux-specific Checks ────────────────────────────────────────────────

    def _check_linux_rwx_memory(
        self,
        v: ProcessFeatureVector,
    ) -> list[DetectorResult]:
        """Flag Linux processes with anonymous read-write-execute memory regions.

        Corroborating indicators are required before escalating to HIGH or CRITICAL
        severity. This prevents false positives from legitimate JIT engines:
        V8 (Electron/Chromium/Node.js), Java HotSpot, Python Numba, Mesa shaders.

        Corroborating indicators (any combination):
            - External network connections from a non-system path → possible C2 traffic
              (connections from /usr/bin, /usr/share, /opt, etc. are ignored: browsers,
              IDEs, and update daemons legitimately make external connections)
            - Executable NOT in system path → unusual install location
            - Parent process mismatch when NOT in system path → unexpected spawn chain
              (system-installed software — IDEs, browsers, daemons — can be launched
              from any parent: terminal, desktop launcher, D-Bus activation, etc.)

        Severity matrix:
            malfind_hits > 0, 0 corroboration → MEDIUM  (likely JIT — informational)
            malfind_hits > 0, 1 corroboration → HIGH
            malfind_hits ≥ 3, 2+ corroboration → CRITICAL
            vad_rwx_count > 5, 0 corroboration → not reported  (too noisy alone)
            vad_rwx_count > 5, 1+ corroboration → MEDIUM

        Note: compromised system binaries (e.g., backdoored curl/bash) are handled
        separately by _check_linux_compromised_binary().
        """
        results = []

        # JIT-capable processes (V8, JVM, Mesa, etc.) always have anonymous RWX pages
        # as a side-effect of dynamic code generation. No amount of corroboration from
        # other memory indicators can disambiguate them from malware at this level
        # because they are specifically designed to generate executable code at runtime.
        # These processes are handled by _check_linux_compromised_binary() instead,
        # which looks at the combination of RWX + active external connections.
        if v.name.lower() in _LINUX_JIT_PROCESSES:
            return results

        # Collect corroborating signals that distinguish malware from JIT.
        # Both external connections AND parent mismatch are only suspicious when the
        # process is ALSO outside a standard system path:
        #   - System-installed software legitimately makes external connections
        #     (browsers, IDEs like VSCode, update daemons, telemetry agents).
        #   - System software can be launched from any parent (terminal, D-Bus,
        #     desktop launchers, xdg-open, etc.) without being malicious.
        not_system_path = not v.is_system_path
        has_suspicious_net = v.external_connection_count > 0 and not_system_path
        has_parent_mismatch = bool(v.parent_name_mismatch) and not_system_path
        corroboration = int(has_suspicious_net) + int(not_system_path) + int(has_parent_mismatch)

        if v.malfind_hits > 0:
            corroborating_parts: list[str] = []
            if has_suspicious_net:
                corroborating_parts.append(
                    f"{v.external_connection_count} external connection(s) from non-standard path"
                )
            if not_system_path:
                corroborating_parts.append("non-standard executable path")
            if has_parent_mismatch:
                corroborating_parts.append("unexpected parent process")

            if corroboration >= 2:
                severity = FindingSeverity.CRITICAL if v.malfind_hits >= 3 else FindingSeverity.HIGH
                confidence = 0.90 if v.malfind_hits >= 3 else 0.78
                context = f"Corroborating indicators: {', '.join(corroborating_parts)}."
            elif corroboration == 1:
                severity = FindingSeverity.HIGH if v.malfind_hits >= 3 else FindingSeverity.MEDIUM
                confidence = 0.70
                context = f"Additional indicator: {corroborating_parts[0]}."
            else:
                # RWX with no additional context → likely JIT, flag informally
                severity = FindingSeverity.MEDIUM
                confidence = 0.40
                context = (
                    "No corroborating indicators. Likely JIT-compiled code "
                    "(V8, JVM, Mesa shaders). Low probability of malicious intent."
                )

            results.append(
                DetectorResult(
                    detector=self.name,
                    pid=v.pid,
                    process_name=v.name,
                    severity=severity,
                    title=f"Anonymous RWX memory regions: {v.name} ({v.malfind_hits} region(s))",
                    description=(
                        f"Process {v.name!r} (PID {v.pid}) has {v.malfind_hits} anonymous "
                        f"memory region(s) with read-write-execute (RWX) protection. "
                        f"On Linux, RWX mappings can indicate shellcode staging or process "
                        f"injection, but are also produced by JIT engines. {context}"
                    ),
                    mitre_technique="T1055",
                    mitre_technique_name="Process Injection",
                    evidence={
                        "malfind_hits": v.malfind_hits,
                        "vad_rwx_count": v.vad_rwx_count,
                        "corroboration_score": corroboration,
                        "external_connections": v.external_connection_count,
                        "is_system_path": v.is_system_path,
                        "parent_mismatch": v.parent_name_mismatch,
                    },
                    confidence=confidence,
                )
            )

        elif v.vad_rwx_count > 5:
            # High VAD RWX count is very common on Linux — skip unless corroborated
            if corroboration >= 1:
                results.append(
                    DetectorResult(
                        detector=self.name,
                        pid=v.pid,
                        process_name=v.name,
                        severity=FindingSeverity.MEDIUM,
                        title=f"Elevated RWX VAD count: {v.name} ({v.vad_rwx_count} region(s))",
                        description=(
                            f"Process {v.name!r} (PID {v.pid}) has {v.vad_rwx_count} memory "
                            f"regions with execute-write permission flags, combined with "
                            f"additional indicators. May indicate dynamic code generation "
                            f"outside a known JIT engine."
                        ),
                        mitre_technique="T1055",
                        mitre_technique_name="Process Injection",
                        evidence={
                            "vad_rwx_count": v.vad_rwx_count,
                            "corroboration_score": corroboration,
                        },
                        confidence=0.50,
                    )
                )
        return results

    def _check_linux_compromised_binary(
        self,
        v: ProcessFeatureVector,
    ) -> list[DetectorResult]:
        """Detect potentially compromised Linux system binaries (Gap 1 coverage).

        A non-JIT process running from a standard system path that has BOTH:
          - Anonymous RWX memory pages (malfind_hits > 0) — not expected for
            utilities that do not use a JIT compiler
          - Active external network connections — unusual for tools like ls, grep,
            or system daemons that do not phone home

        This combination strongly suggests the binary was backdoored (T1554) or
        an attacker injected code via LD_PRELOAD (T1574.006).  This check covers
        the gap left by _check_linux_rwx_memory(), which cannot escalate beyond
        MEDIUM for system-path processes to avoid false positives from JIT runtimes.

        MITRE ATT&CK:
            T1554   — Compromise Host Software Binary
            T1574.006 — Hijack Execution Flow: LD_PRELOAD
        """
        results = []

        # Only applies to system-path processes (non-system paths already caught by RWX)
        if not v.is_system_path:
            return results

        # Need both RWX pages and active external connections
        if v.malfind_hits == 0 or v.external_connection_count == 0:
            return results

        # JIT-capable processes legitimately have RWX pages — skip them
        if v.name.lower() in _LINUX_JIT_PROCESSES:
            return results

        severity = FindingSeverity.CRITICAL if v.malfind_hits >= 3 else FindingSeverity.HIGH
        confidence = 0.85 if v.malfind_hits >= 3 else 0.75

        results.append(
            DetectorResult(
                detector=self.name,
                pid=v.pid,
                process_name=v.name,
                severity=severity,
                title=f"Possible compromised system binary: {v.name}",
                description=(
                    f"System binary {v.name!r} (PID {v.pid}) has {v.malfind_hits} anonymous "
                    f"RWX memory region(s) combined with {v.external_connection_count} external "
                    f"network connection(s). Non-JIT system utilities never legitimately allocate "
                    f"anonymous executable pages. This may indicate binary backdooring (T1554), "
                    f"LD_PRELOAD injection (T1574.006), or an in-memory implant."
                ),
                mitre_technique="T1554",
                mitre_technique_name="Compromise Host Software Binary",
                evidence={
                    "malfind_hits": v.malfind_hits,
                    "external_connections": v.external_connection_count,
                    "is_system_path": v.is_system_path,
                    "vad_rwx_count": v.vad_rwx_count,
                },
                confidence=confidence,
            )
        )
        return results

    def _check_linux_suspicious_path(
        self,
        v: ProcessFeatureVector,
        extraction: ExtractionResult,
    ) -> list[DetectorResult]:
        """Flag Linux processes executing from suspicious directories (/tmp, /dev/shm, etc.)."""
        results = []
        _SUSPICIOUS_LINUX_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/")  # noqa: S108

        # Get full exe path from process tree (image_file_name)
        proc = extraction.process_tree.flat_map.get(v.pid) if extraction.process_tree else None
        exe_path = (proc.image_file_name if proc else "") or ""

        if exe_path:
            for sus_dir in _SUSPICIOUS_LINUX_DIRS:
                if exe_path.startswith(sus_dir):
                    results.append(
                        DetectorResult(
                            detector=self.name,
                            pid=v.pid,
                            process_name=v.name,
                            severity=FindingSeverity.HIGH,
                            title=f"Process executing from suspicious directory: {v.name}",
                            description=(
                                f"Process {v.name!r} (PID {v.pid}) is executing from "
                                f"{exe_path!r}. Legitimate system services never execute from "
                                f"world-writable directories like /tmp or /dev/shm. "
                                f"This is a strong indicator of malware persistence or fileless execution."
                            ),
                            mitre_technique="T1204.002",
                            mitre_technique_name="User Execution: Malicious File",
                            evidence={"exe_path": exe_path},
                            confidence=0.90,
                        )
                    )
                    break
        return results

    def _check_linux_suspicious_dll(
        self,
        v: ProcessFeatureVector,
        extraction: ExtractionResult,
    ) -> list[DetectorResult]:
        """Flag Linux processes with shared libraries from suspicious locations.

        Distinguishes between:
          - memfd / anonymous mappings: expected from JIT engines (V8, JVM, Mesa GLSL)
            and from processes with shader compilation. Flagged as LOW severity unless
            corroborating indicators exist.
          - Actual filesystem paths in suspicious directories (/tmp, /dev/shm, etc.):
            flagged as HIGH regardless of other indicators.

        Args:
            v: Feature vector for the process.
            extraction: Full extraction result to access actual DLL path data.
        """
        results = []
        if v.suspicious_dll_count == 0:
            return results

        # Inspect actual DLL entries to distinguish memfd/anon (JIT) from real paths
        dlls = extraction.dlls.get(v.pid, []) if extraction.dlls else []
        path_suspicious: list[str] = []  # actual filesystem paths in bad dirs
        jit_suspicious: list[str] = []  # memfd:, [anon], or no path at all

        for dll in dlls:
            if not dll.is_suspicious:
                continue
            p = getattr(dll, "full_path", None) or ""
            if not p or p.startswith("[") or "memfd:" in p:
                jit_suspicious.append(p or "<anon>")
            else:
                path_suspicious.append(p)

        # Edge case: dlls dict empty but count > 0 → treat as JIT-uncertain
        if not path_suspicious and not jit_suspicious and v.suspicious_dll_count > 0:
            jit_suspicious = ["<unknown>"] * v.suspicious_dll_count

        # Corroborating signals.
        # External connections are only suspicious when the process is ALSO outside a
        # standard system path — same rationale as in _check_linux_rwx_memory.
        not_system_path = not v.is_system_path
        has_suspicious_net = v.external_connection_count > 0 and not_system_path
        has_parent_mismatch = bool(v.parent_name_mismatch)
        corroboration = int(has_suspicious_net) + int(not_system_path) + int(has_parent_mismatch)

        # ── Real suspicious filesystem paths → HIGH regardless ─────────────────
        if path_suspicious:
            results.append(
                DetectorResult(
                    detector=self.name,
                    pid=v.pid,
                    process_name=v.name,
                    severity=FindingSeverity.HIGH,
                    title=(
                        f"Shared library from suspicious path: {v.name} "
                        f"({len(path_suspicious)} lib(s))"
                    ),
                    description=(
                        f"Process {v.name!r} (PID {v.pid}) loaded {len(path_suspicious)} shared "
                        f"library mapping(s) from suspicious filesystem locations "
                        f"({path_suspicious[:3]}). Possible LD_PRELOAD injection, rootkit "
                        f"library hooking, or a fileless implant in a world-writable directory."
                    ),
                    mitre_technique="T1574.006",
                    mitre_technique_name="Hijack Execution Flow: LD_PRELOAD",
                    evidence={
                        "suspicious_paths": path_suspicious[:10],
                        "count": len(path_suspicious),
                    },
                    confidence=0.85,
                )
            )

        # ── memfd / anonymous mappings → severity depends on corroboration ──────
        if jit_suspicious:
            if corroboration >= 1:
                severity = FindingSeverity.MEDIUM
                confidence = 0.55
                extra = (
                    f" Additionally, {corroboration} corroborating indicator(s) were "
                    f"detected, increasing suspicion."
                )
            else:
                severity = FindingSeverity.LOW
                confidence = 0.30
                extra = (
                    " No additional indicators. Likely JIT-compiled code "
                    "(V8, JVM, Mesa GLSL shaders) — low probability of malicious intent."
                )

            results.append(
                DetectorResult(
                    detector=self.name,
                    pid=v.pid,
                    process_name=v.name,
                    severity=severity,
                    title=(
                        f"Anonymous shared library mapping: {v.name} "
                        f"({len(jit_suspicious)} memfd/anon entry(ies))"
                    ),
                    description=(
                        f"Process {v.name!r} (PID {v.pid}) has {len(jit_suspicious)} anonymous "
                        f"memory mapping(s) (memfd / [anon]) in its shared library list.{extra}"
                    ),
                    mitre_technique="T1574.006",
                    mitre_technique_name="Hijack Execution Flow: LD_PRELOAD",
                    evidence={
                        "anon_count": len(jit_suspicious),
                        "corroboration_score": corroboration,
                    },
                    confidence=confidence,
                )
            )

        return results

    # ─── Individual Windows Checks ────────────────────────────────────────────

    def _check_adaptive_threshold(
        self,
        v: ProcessFeatureVector,
    ) -> list[DetectorResult]:
        """Re-evaluate threat score using process-type-specific thresholds.

        System-critical processes are only flagged at a higher score to
        reduce false positives on processes the ML model was not optimally
        trained for.
        """
        results = []
        proc_lower = v.name.lower()
        adaptive_threshold = ADAPTIVE_THRESHOLDS.get(proc_lower, 0.65)

        # Process was marked malicious by ML but is a critical system process
        # → only flag if it also exceeds the adaptive threshold
        if v.is_malicious and proc_lower in ADAPTIVE_THRESHOLDS:
            if v.threat_score < adaptive_threshold:
                # Downgrade: score is below adaptive threshold, this is likely a FP
                results.append(
                    DetectorResult(
                        detector=self.name,
                        pid=v.pid,
                        process_name=v.name,
                        severity=FindingSeverity.INFO,
                        title=f"ML flag downgraded: {v.name} below adaptive threshold",
                        description=(
                            f"Process {v.name!r} (PID {v.pid}) was flagged malicious by ML "
                            f"with score {v.threat_score:.3f}, but adaptive threshold for this "
                            f"critical system process is {adaptive_threshold:.2f}. "
                            f"Treated as informational (likely false positive)."
                        ),
                        mitre_technique="",
                        evidence={
                            "threat_score": v.threat_score,
                            "adaptive_threshold": adaptive_threshold,
                            "is_system_critical": True,
                        },
                        confidence=0.3,
                    )
                )
            else:
                # Confirmed high-confidence malicious system process
                results.append(
                    DetectorResult(
                        detector=self.name,
                        pid=v.pid,
                        process_name=v.name,
                        severity=FindingSeverity.CRITICAL,
                        title=f"Critical system process anomaly: {v.name}",
                        description=(
                            f"Critical system process {v.name!r} (PID {v.pid}) scored "
                            f"{v.threat_score:.3f}, exceeding the adaptive threshold of "
                            f"{adaptive_threshold:.2f} for this process type. "
                            f"High-confidence malicious activity."
                        ),
                        mitre_technique="T1036.005",
                        mitre_technique_name="Masquerading: Match Legitimate Name or Location",
                        evidence={
                            "threat_score": v.threat_score,
                            "adaptive_threshold": adaptive_threshold,
                        },
                        confidence=min(v.threat_score, 1.0),
                    )
                )

        return results

    def _check_parent_relationship(
        self,
        v: ProcessFeatureVector,
        pid_to_name: dict[int, str],
    ) -> list[DetectorResult]:
        """Check that process is spawned by a valid parent."""
        results = []
        proc_lower = v.name.lower()

        if proc_lower not in VALID_PARENT_MAP:
            return results

        valid_parents = VALID_PARENT_MAP[proc_lower]
        actual_parent_name = pid_to_name.get(v.ppid, "unknown").lower()

        # Special case: parent PID 0 or not found is OK for some processes
        if not valid_parents or actual_parent_name in valid_parents:
            return results

        results.append(
            DetectorResult(
                detector=self.name,
                pid=v.pid,
                process_name=v.name,
                severity=FindingSeverity.HIGH,
                title=f"Unexpected parent process: {v.name} spawned by {actual_parent_name}",
                description=(
                    f"Process {v.name!r} (PID {v.pid}) is spawned by "
                    f"{actual_parent_name!r} (PID {v.ppid}), but valid parents are: "
                    f"{sorted(valid_parents)}. "
                    f"This may indicate process injection or malicious spawning."
                ),
                mitre_technique="T1036.005",
                mitre_technique_name="Masquerading: Match Legitimate Name or Location",
                evidence={
                    "actual_parent": actual_parent_name,
                    "valid_parents": sorted(valid_parents),
                    "ppid": v.ppid,
                },
                confidence=0.85,
            )
        )
        return results

    def _check_system_process_path(
        self,
        v: ProcessFeatureVector,
    ) -> list[DetectorResult]:
        """Check that system-only processes run from System32."""
        results = []
        proc_lower = v.name.lower()

        if proc_lower not in SYSTEM_ONLY_PROCESSES:
            return results

        # is_system_path is True if path contains System32/syswow64/etc.
        if not v.is_system_path:
            results.append(
                DetectorResult(
                    detector=self.name,
                    pid=v.pid,
                    process_name=v.name,
                    severity=FindingSeverity.CRITICAL,
                    title=f"System process running outside System32: {v.name}",
                    description=(
                        f"Critical system process {v.name!r} (PID {v.pid}) is NOT "
                        f"running from a system directory. This is a strong indicator of "
                        f"malware masquerading as a legitimate system process."
                    ),
                    mitre_technique="T1036.005",
                    mitre_technique_name="Masquerading: Match Legitimate Name or Location",
                    evidence={
                        "is_system_path": v.is_system_path,
                        "process_name": v.name,
                    },
                    confidence=0.95,
                )
            )
        return results

    def _check_suspicious_path(
        self,
        v: ProcessFeatureVector,
    ) -> list[DetectorResult]:
        """Flag processes executing from Temp, AppData, Downloads, etc."""
        results = []

        # We infer path from is_system_path=False + threat indicators
        # ProcessFeatureVector doesn't store the raw path, but DLL paths do
        # Use suspicious_dll_count > 0 from user dirs as a proxy
        if v.suspicious_dll_count > 3 and not v.is_system_path and v.threat_score > 0.4:
            results.append(
                DetectorResult(
                    detector=self.name,
                    pid=v.pid,
                    process_name=v.name,
                    severity=FindingSeverity.MEDIUM,
                    title=f"Multiple suspicious DLLs from user directories: {v.name}",
                    description=(
                        f"Process {v.name!r} (PID {v.pid}) loaded {v.suspicious_dll_count} DLLs "
                        f"from user-writable directories (Temp, AppData, Downloads). "
                        f"Threat score: {v.threat_score:.3f}. Possible DLL side-loading."
                    ),
                    mitre_technique="T1574.001",
                    mitre_technique_name="Hijack Execution Flow: DLL Search Order Hijacking",
                    evidence={
                        "suspicious_dll_count": v.suspicious_dll_count,
                        "threat_score": v.threat_score,
                    },
                    confidence=0.7,
                )
            )
        return results
