# ForensIQ — Memory Forensics & Threat Hunting Platform

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-1.0.0-brightgreen.svg)](https://github.com/Dacr2153/ForensIQ)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-orange.svg)](.github/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-885%20passed-success.svg)](tests/)
[![Volatility 3](https://img.shields.io/badge/Volatility%203-2.28.0-blueviolet.svg)](https://github.com/volatilityfoundation/volatility3)
[![XGBoost](https://img.shields.io/badge/XGBoost-3.2.0-4B0082.svg)](https://github.com/dmlc/xgboost)

**ForensIQ** is a **memory forensics and threat hunting platform** designed to detect **fileless malware** and memory-resident threats in Windows and Linux memory dumps. It analyzes memory dumps **100% offline** and produces actionable forensic reports — without sending data to any external API.

> **WARNING:** For authorized defensive forensics only. Analyze only systems you own or have explicit written authorization to examine.

---

## Table of Contents

- [Description](#description)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Environment Variables](#environment-variables)
- [Usage](#usage)
- [CLI Commands](#cli-commands)
- [Live Memory Analysis (Linux)](#live-memory-analysis-linux)
- [Machine Learning Model](#machine-learning-model)
- [Outputs and Reports](#outputs-and-reports)
- [Database](#database)
- [Integrations](#integrations)
- [Testing](#testing)
- [Linting and Formatting](#linting-and-formatting)
- [Docker](#docker)
- [CI/CD Pipeline](#cicd-pipeline)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [Contributing](#contributing)
- [License and Ethical Use](#license-and-ethical-use)

---

## Description

When a Windows system is compromised, **fileless malware** operates exclusively in RAM and disappears on reboot. Memory dumps contain the evidence — but extracting and classifying hundreds of processes manually is infeasible.

ForensIQ automates the entire workflow:

1. **Artifact extraction** from the dump via **Volatility 3** (`pslist`, `netscan`, `dlllist`, `malfind`, `vadinfo`, `handles`, `svcscan`).
2. **Feature engineering** — computes 20 per-process features (Shannon entropy, parent-child heuristics, VAD anomalies, network behavior, etc.).
3. **Classification** with an **XGBoost + IsolationForest** ensemble trained on CIC-MalMem2022, with **SHAP** explanations for every process.
4. **Pattern detection** via 7 detector plugins (DKOM rootkits, malicious mutexes, anomalous services, PE injection, string IOCs, threat intelligence).
5. **YARA rule generation** assisted by a local LLM (**Ollama**), auto-detected and with no API cost.
6. **Reporting** as self-contained HTML, structured JSON, and **STIX 2.1** bundles.

**Results include:**
- Process ranking by malicious probability, with SHAP-based attribution.
- Timeline of events mapped to **MITRE ATT&CK** techniques.
- Validated YARA rules ready for SIEM/EDR deployment.
- Navigable HTML report and JSON for SOAR integration.

---

## Key Features

| Area | Capability |
|---|---|
| **Extraction** | Volatility 3 integrated: processes, network, DLLs, injection, VAD, handles, services |
| **ML Classification** | XGBoost + IsolationForest + SHAP, trained on CIC-MalMem2022 (ROC-AUC 1.000) |
| **Detection** | 7 plugins: process anomalies, DKOM cross-view, mutex, services, PE headers, string IOCs, threat intel |
| **YARA Rules** | Automated generation and validation via local LLM (Ollama, auto-detects installed model) |
| **Live Memory** | Linux live RAM analysis via `/proc/kcore` or **LiME**, with automatic ISF construction |
| **Dump Diff** | Compare two dumps: new/disappeared/changed processes, connections, DLLs, injections |
| **Reports** | Self-contained HTML + structured JSON + **STIX 2.1** export |
| **Threat Intel** | Hash lookups on **VirusTotal** / **MalwareBazaar** (optional, with local cache and rate-limiting) |
| **History** | SQLite persistence of analysis history and threat-intel cache |
| **TUI** | Interactive menu-driven interface via questionary + Rich |
| **Offline-first** | Works without connectivity; AI and threat intel are optional and degrade gracefully |

---

## Architecture

```
Memory Dump (.raw / .dmp / .vmem)   or   Linux Live RAM (/proc/kcore · LiME)
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│  EXTRACTION — Volatility 3                                      │
│  pslist · pstree · cmdline · netscan · dlllist                  │
│  vadinfo · malfind · handles · svcscan                          │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│  FEATURE ENGINEERING (20 per-process)                           │
│  Shannon entropy · path depth · parent-child heuristics         │
│  suspicious DLLs · VAD anomalies · network behavior             │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│  ML CLASSIFICATION                                              │
│  XGBoost + IsolationForest (CIC-MalMem2022)                     │
│  SHAP TreeExplainer — per-process attribution                   │
└───────────────┬───────────────────────────────┬─────────────────┘
                │                               │
                ▼                               ▼
┌──────────────────────────┐  ┌──────────────────────────────────┐
│  DETECTOR PLUGINS        │  │  YARA RULES (Local LLM)          │
│  anomalies · cross-view  │  │  Ollama auto-detect → Jinja2     │
│  mutex · services · PE   │  │  prompt → yara-python validation  │
│  strings/IOC · threat    │  └──────────────────────────────────┘
│  intel                   │
└──────────────┬───────────┘  ┌──────────────────────────────────┘
               │              │
               └──────┬───────┘
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│  REPORTING                                                      │
│  HTML + JSON + STIX 2.1                                         │
│  Process ranking · MITRE ATT&CK timeline · YARA rules           │
│  SQLite history · STIX bundle export                            │
└─────────────────────────────────────────────────────────────────┘
```

### Detector Plugins

| Detector | What It Detects | MITRE ATT&CK |
|---|---|---|
| `ProcessAnomalyDetector` | Adaptive threshold, masquerading, anomalous parent-child relationships | T1036, T1055 |
| `ProcessAnomalyDetectorLinux` | Linux RWX memory with corroboration scoring, compromised system binaries, suspicious paths/DLLs | T1055, T1574 |
| `CrossViewDetector` | DKOM / rootkits: `psscan` vs `pslist` (hidden processes) | T1014 |
| `HandlesMutexDetector` | Malicious mutexes and registry handles | T1480 |
| `ServicesScanDetector` | Malicious Windows services via `svcscan` | T1543 |
| `PEHeaderDetector` | PE header analysis: suspicious imports, packer sections, process hollowing | T1055, T1620 |
| `MalfindStringsDetector` | String IOC extraction: C2 URLs, IPs, registry keys, Linux shell commands | T1071, T1059 |
| `ThreatIntelDetector` | VT / MalwareBazaar hash lookups on suspicious DLLs | — |

---

## Technology Stack

| Category | Technology | Version | Purpose |
|---|---|---|---|
| **Language** | Python | ≥ 3.12 | Core runtime |
| **Forensics** | Volatility 3 | 2.28.0 | Memory artifact extraction |
| **ML** | XGBoost | 3.2.0 | Threat classification |
| **ML** | scikit-learn | 1.8.0 | CalibratedClassifierCV, IsolationForest |
| **ML** | SHAP | 0.51.0 | Per-process feature attribution |
| **ML** | Optuna | 4.8.0 | Hyperparameter optimization |
| **Data** | pandas | 3.0.2 | Feature matrix manipulation |
| **Data** | NumPy | 2.4.4 | Numerical operations |
| **YARA** | yara-python | 4.5.4 | Rule compilation and matching |
| **LLM** | Ollama | — | Local LLM for YARA generation |
| **HTTP** | httpx | 0.28.1 | Async HTTP client (Ollama, VT, MB) |
| **CLI** | Typer | 0.25.1 | Command-line interface |
| **TUI** | Rich | 15.0.0 | Terminal UI and progress bars |
| **Settings** | Pydantic | 2.13.3 | Data validation and settings management |
| **Templating** | Jinja2 | 3.1.6 | HTML report templates |
| **Logging** | structlog | 25.5.0 | Structured logging |
| **Database** | aiosqlite | 0.22.1 | Async SQLite for history |
| **Standards** | STIX 2.1 | 3.0.2 | Threat intelligence export |
| **Build** | setuptools | ≥ 61 | PEP 517/518 packaging |
| **Linting** | Ruff | 0.15.12 | Linting and formatting |
| **Type Check** | MyPy | 2.0.0 | Static type analysis (strict mode) |
| **Security** | Bandit | 1.9.4 | Security audit |
| **Testing** | Pytest | 9.0.3 | Test framework |

---

## Project Structure

```
forens_iq/
├── .github/workflows/
│   └── ci.yml                    # GitHub Actions CI pipeline
├── ml/
│   └── data/                     # Trained models (.joblib, .json) [gitignored]
├── scripts/
│   ├── setup_env.sh              # Automated environment setup
│   ├── download_datasets.sh      # CIC-MalMem2022 dataset download helper
│   └── demo.sh                   # End-to-end demo with public sample
├── src/forensiq/
│   ├── __init__.py               # Package metadata
│   ├── __main__.py               # Entry point (python -m forensiq)
│   ├── cli.py                    # Typer CLI: analyze, train, check, live, diff, menu
│   ├── config/
│   │   └── settings.py           # Pydantic Settings with .env support
│   ├── models/
│   │   ├── process.py            # ProcessArtifact, ProcessNode, ProcessTree
│   │   ├── network.py            # NetworkConnection
│   │   ├── artifact.py           # DLLEntry, VADEntry, MalfindRegion
│   │   ├── features.py           # ProcessFeatureVector (20 ML features)
│   │   ├── report.py             # ForensiqReport, TimelineEvent, YaraResult
│   │   ├── mitre.py              # MITRE ATT&CK technique mapping
│   │   └── threat_intel.py       # ThreatIntelResult
│   ├── acquisition/
│   │   ├── volatility_runner.py  # Volatility 3 subprocess runner (sync + async)
│   │   ├── live_memory.py        # Live Linux: /proc/kcore + LiME acquisition
│   │   └── linux_isf.py          # BTF parser + ISF generator for Volatility 3
│   ├── extraction/
│   │   ├── orchestrator.py       # ExtractionResult builder, runs all extractors
│   │   ├── process_extractor.py  # Process tree from pslist + cmdline
│   │   ├── dll_extractor.py      # DLL lists from dlllist
│   │   ├── dll_hasher.py         # Genuine SHA-256 content hashing
│   │   ├── network_extractor.py  # Network connections from netscan
│   │   ├── vad_extractor.py      # VAD/malfind extraction
│   │   ├── handles_extractor.py  # Windows handles (mutexes, registry)
│   │   └── services_extractor.py # Windows services from svcscan
│   ├── features/
│   │   ├── engineer.py           # FeatureVectorBuilder: 20 features per process
│   │   ├── entropy.py            # Shannon entropy calculations
│   │   └── heuristics.py         # System path, parent-child, encoding checks
│   ├── ml/
│   │   ├── classifier.py         # XGBoost + CalibratedClassifierCV + IsolationForest
│   │   ├── explainer.py          # SHAP TreeExplainer
│   │   └── training/
│   │       └── train.py          # Model training script
│   ├── detectors/
│   │   ├── base.py               # BaseDetector ABC, DetectorResult, FindingSeverity
│   │   ├── registry.py           # DetectorRegistry with default builders
│   │   ├── process_anomaly.py    # Windows process anomaly detection
│   │   ├── process_anomaly_linux.py # Linux process anomaly detection
│   │   ├── cross_view.py         # DKOM rootkit detection
│   │   ├── handles_mutex.py      # Mutex/handle malware detection
│   │   ├── services_scan.py      # Malicious service detection
│   │   ├── pe_header.py          # PE header analysis
│   │   ├── malfind_strings.py    # String IOC extraction
│   │   └── threat_intel.py       # VT + MalwareBazaar lookups
│   ├── llm/
│   │   └── ollama_client.py      # httpx async client for Ollama API
│   ├── integrations/
│   │   ├── _base.py              # BatchLookupMixin (rate-limited)
│   │   ├── virustotal.py         # VT API v3 client
│   │   └── malwarebazaar.py      # MalwareBazaar API client
│   ├── reporting/
│   │   ├── builder.py            # HTML report via Jinja2
│   │   ├── executive.py          # Executive summary via LLM with fallback
│   │   ├── stix_exporter.py      # STIX 2.1 bundle export
│   │   └── templates/
│   │       └── report.html.j2    # Self-contained HTML template
│   ├── yara/
│   │   └── generator.py          # YARA rule generation via Ollama
│   ├── db/
│   │   └── manager.py            # aiosqlite async DB manager
│   ├── cache/
│   │   └── plugin_cache.py       # Disk-based Volatility output cache
│   ├── pipeline/
│   │   ├── analysis_pipeline.py  # Main analysis pipeline orchestrator
│   │   └── diff_pipeline.py      # Dump comparison pipeline
│   ├── tui/
│   │   ├── menu.py               # Interactive Rich menu
│   │   └── menu_live.py          # Live analysis wizard
│   └── utils/
│       ├── logger.py             # structlog-based logger
│       ├── exceptions.py         # Custom exception hierarchy
│       ├── hexdump.py            # Volatility hexdump decoder
│       └── filename.py           # Filename sanitization
├── tests/
│   ├── unit/                     # Unit tests (no external dependencies)
│   └── integration/              # Integration tests (may use fixtures)
├── .env.example                  # Environment variable template
├── .gitignore
├── Makefile                      # Build, test, lint, demo targets
├── pyproject.toml                # PEP 517/518 project configuration
├── requirements.txt              # Pinned dependencies (pip-compile output)
└── README.md
```

---

## Prerequisites

| Component | Version / Note |
|---|---|
| Python | **3.12+** |
| YARA (system library) | Any recent version (`libyara-dev` / `yara` package) |
| Volatility 3 | 2.28.0 (installed via pip) |
| Ollama + model | **Optional** — only for YARA generation (recommended: `mistral:7b`) |
| ML Model | Included in repository (`ml/data/`) or trainable from CIC-MalMem2022 |
| Hardware | 4 GB+ RAM; GPU acceleration optional for LLM inference |

### System Dependencies

**Arch Linux:**

```bash
sudo pacman -S yara python python-pip
```

**Ubuntu / Debian:**

```bash
sudo apt-get install yara libyara-dev python3-pip python3-venv
```

**Fedora / RHEL:**

```bash
sudo dnf install yara-devel python3-pip
```

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Dacr2153/ForensIQ.git
cd ForensIQ
```

### 2. Create and activate a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
pip install -e .
```

> **Note:** `make setup` automates steps 2 and 3 (see [Makefile](Makefile)).

### 4. Verify the installation

```bash
forensiq check
```

This verifies Volatility 3, yara-python, the ML model, and Ollama connectivity.

### 5. (Optional) Install Ollama for YARA generation

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull mistral:7b
ollama serve &
```

ForensIQ auto-detects any installed model and falls back gracefully if none is available.

---

## Configuration

ForensIQ is configured via environment variables or a `.env` file:

```bash
cp .env.example .env
```

Settings are managed through Pydantic `BaseSettings` with the `FORENSIQ_` prefix. See [Environment Variables](#environment-variables) for the full list.

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `FORENSIQ_VOLATILITY_PATH` | `vol` | Path to the Volatility 3 executable |
| `FORENSIQ_OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama API server URL |
| `FORENSIQ_OLLAMA_MODEL` | `mistral:latest` | Preferred LLM model (auto-fallback to any installed) |
| `FORENSIQ_OLLAMA_TIMEOUT` | `120` | Timeout in seconds for LLM responses |
| `FORENSIQ_MODEL_PATH` | `./ml/data/forensiq_model.joblib` | Path to the trained XGBoost model |
| `FORENSIQ_REPORTS_DIR` | `./reports` | Output directory for HTML/JSON reports |
| `FORENSIQ_YARA_RULES_DIR` | `./yara_rules` | Output directory for generated YARA rules |
| `FORENSIQ_DB_PATH` | `~/.forensiq/forensiq.db` | SQLite database for analysis history and threat-intel cache |
| `FORENSIQ_MAX_PROCESSES_ANALYZE` | `500` | Maximum processes to analyze (0 = unlimited) |
| `FORENSIQ_THREAT_THRESHOLD` | `0.65` | Probability threshold for malicious classification (0.0–1.0) |
| `FORENSIQ_YARA_GENERATE` | `true` | Enable/disable YARA rule generation |
| `FORENSIQ_DLL_ROOT` | *(empty)* | Root directory for DLL content hashing (mount point of suspect system) |
| `FORENSIQ_VT_API_KEY` | *(empty)* | VirusTotal API v3 key (leave empty to disable) |
| `FORENSIQ_LOG_LEVEL` | `INFO` | Logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `FORENSIQ_LOG_FORMAT` | `console` | Log format: `console` (human-readable) or `json` (structured, ELK/Splunk compatible) |

> **Security:** Never commit `.env` to version control — it is ignored by `.gitignore`.

---

## Usage

### Interactive menu (recommended)

```bash
forensiq menu
```

### Analyze a Windows memory dump

```bash
# Full analysis
forensiq analyze --dump /path/to/dump.raw

# Skip YARA generation (faster, no Ollama required)
forensiq analyze --dump /path/to/dump.raw --no-yara

# Adjust classification threshold (default: 0.65)
forensiq analyze --dump /path/to/dump.raw --threshold 0.75

# Export STIX 2.1 bundle
forensiq analyze --dump /path/to/dump.raw --output-stix ./stix

# Stream incremental results + force re-analysis
forensiq analyze --dump /path/to/dump.raw --stream --force
```

> **Note:** `sudo` may be required for Volatility 3 to access system symbols and dump files.

### Compare two memory dumps (diff)

```bash
forensiq diff --before /path/baseline.raw --after /path/post_incident.raw
```

### Analyze live Linux memory

```bash
# Via /proc/kcore (standard kernels)
sudo forensiq live

# Via LiME (hardened kernels without /proc/kcore)
sudo forensiq live --lime
sudo forensiq live --build-lime   # auto-compile lime.ko
sudo forensiq live --build-isf    # generate Volatility 3 ISF
```

### Train the ML model

```bash
forensiq train --data /path/to/dataset.parquet
```

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Analysis completed — **no threats found** |
| `1` | Analysis completed — **malicious processes detected** |
| `2` | Critical error during analysis (check logs) |
| `3` | Degraded analysis (ML unavailable, incomplete results) |

---

## CLI Commands

```
forensiq [COMMAND]
```

| Command | Description |
|---|---|
| `analyze` | Analyze a Windows memory dump end-to-end |
| `train` | Train the XGBoost classifier on CIC-MalMem2022 |
| `check` | Verify system requirements and tool availability |
| `live` | Analyze live Linux memory via `/proc/kcore` or LiME |
| `diff` | Compare two memory dumps |
| `menu` | Launch the interactive TUI console menu |
| `version` | Print version and component information |

### `analyze` Options

| Option | Description |
|---|---|
| `-d, --dump` | Path to the memory dump file (required) |
| `-o, --output` | Output directory (default: `./reports`) |
| `-t, --threshold` | Threat threshold `0.0–1.0` (overrides `FORENSIQ_THREAT_THRESHOLD`) |
| `--no-yara` | Skip YARA rule generation |
| `--no-html` | Skip HTML report generation |
| `--stream` | Stream incremental results per phase |
| `--force` | Force re-analysis even if dump is cached |
| `--output-stix` | Export STIX 2.1 bundle to specified directory |
| `-l, --log-level` | Log level: `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `--log-format` | Format: `console` or `json` |

Run `forensiq <command> --help` for the complete list of options.

---

## Live Memory Analysis (Linux)

ForensIQ can analyze **running Linux system memory** via two acquisition paths:

| Path | Usage | Requirement |
|---|---|---|
| `/proc/kcore` | Default | `CONFIG_PROC_KCORE=y` (standard kernels) |
| **LiME** | `--lime` | `lime.ko` kernel module compiled for the current kernel (required on `linux-hardened`) |

### Automation

- `--build-lime` clones the LiME repository and compiles `lime.ko` automatically (requires `git`, `make`, `gcc`, and kernel headers).
- `--build-isf` generates the Volatility 3 Linux kernel ISF using BTF + System.map (requires Go, which is auto-installed).

```bash
forensiq check                                   # pre-flight diagnostic
sudo forensiq live                               # /proc/kcore
sudo forensiq live --lime                        # use pre-compiled lime.ko
sudo forensiq live --lime-module /path/lime.ko   # explicit module path
```

---

## Machine Learning Model

ForensIQ includes a pre-trained model on **CIC-MalMem2022** (University of New Brunswick), stored in `ml/data/forensiq_model.joblib` with its metadata JSON and companion IsolationForest model (`forensiq_isolation.joblib`).

### Model Performance

| Metric | Value |
|---|---|
| ROC-AUC | 1.000 |
| Precision | 0.9998 |
| Recall | 1.0000 |
| F1 Score | 0.9999 |
| Test Samples | 11,612 |

### Feature Set (20 per process)

| # | Feature | Description |
|---|---|---|
| 1 | `name_entropy` | Shannon entropy of the process name |
| 2 | `path_entropy` | Shannon entropy of the executable path |
| 3 | `path_depth` | Directory depth of the executable |
| 4 | `is_system_path` | Whether the binary is in a system directory |
| 5 | `parent_child_legitimate` | Heuristic parent-child relationship check |
| 6 | `cmdline_encoded` | Whether the command line contains encoded/obfuscated content |
| 7 | `dll_count` | Total number of loaded DLLs |
| 8 | `suspicious_dll_count` | DLLs loaded from non-standard paths |
| 9 | `network_connections` | Total network connections |
| 10 | `external_connections` | Connections to external IPs |
| 11 | `listening_connections` | Listening (server) sockets |
| 12 | `malfind_hits` | Number of malfind (injection) detections |
| 13 | `vad_rwx_count` | VAD regions with RWX permissions |
| 14 | `thread_count` | Number of threads |
| 15 | `handle_count` | Number of handles |
| 16 | `is_wow64` | Whether the process runs under WoW64 |
| 17 | `session_id` | Windows session ID |
| 18 | `has_suspicious_mutex` | Mutex matches known malware patterns |
| 19 | `pe_import_anomalies` | PE import table anomalies |
| 20 | `string_ioc_count` | Number of string-based IOCs (URLs, IPs, registry keys) |

### Training

```bash
forensiq train --data /path/to/CIC-MalMem2022/dataset.parquet
```

Model integrity is verified before loading (includes a feature-schema hash to detect silent misalignment).

---

## Outputs and Reports

All files are saved to `reports/` (configurable via `FORENSIQ_REPORTS_DIR`):

```
reports/
├── forensiq_20260507_123456.html      ← visual report (open in browser)
├── forensiq_20260507_123456.json      ← structured data for SIEM/SOAR
└── forensiq_20260507_123456.stix.json ← STIX 2.1 bundle (if --output-stix used)
```

### HTML Report

Self-contained (no external dependencies):
- Executive summary with threat level and analysis duration
- Process table sorted by threat score with SHAP attribution
- MITRE ATT&CK technique timeline
- Generated and validated YARA rules
- Interactive SHAP feature importance bars
- Dark theme, responsive design

### JSON Structure

```json
{
  "threat_level": "CRITICAL",
  "total_processes": 87,
  "malicious_count": 2,
  "suspicious_count": 5,
  "ranked_processes": [],
  "timeline": [],
  "yara_results": [],
  "detector_findings": [],
  "mitre_techniques": []
}
```

### YARA Rules

Generated rules are saved to `yara_rules/`:

```yara
rule forensiq_payload_3388 {
    meta:
        author       = "ForensIQ / Mistral 7B"
        threat_level = "critical"
        mitre        = "T1055"
    strings:
        $proc = "payload.exe" nocase
        $mz   = { 4D 5A }
    condition:
        $proc and $mz
}
```

---

## Database

ForensIQ uses **SQLite** (via `aiosqlite`) for:

- **Analysis history:** Stores results of each analysis session (dump SHA-256, threat level, process counts, timestamps).
- **Threat-intel cache:** Caches VT / MalwareBazaar lookups for 24 hours to avoid redundant API calls.
- **YARA rule tracking:** Stores generated rules and their validation status.

Default location: `~/.forensiq/forensiq.db` (configurable via `FORENSIQ_DB_PATH`).

---

## Integrations

### VirusTotal (Optional)

- Uses API v3 for hash-based IOC lookups on suspicious DLLs.
- Rate-limited to 4 requests/minute (free-tier compatible).
- Results cached locally for 24 hours.
- Enable by setting `FORENSIQ_VT_API_KEY` in `.env`.

### MalwareBazaar (Optional)

- Secondary fallback for hashes VirusTotal could not resolve.
- No API key required.
- Retry logic with exponential backoff.

### Ollama (Optional)

- Local LLM inference for YARA rule generation and executive summaries.
- Auto-detects any installed model; falls back to a curated preference order: mistral → llama → qwen → phi → gemma → codellama → deepseek.
- If no model is installed, analysis completes with rule-based (non-AI) content.

### STIX 2.1

- Exports analysis results as a STIX 2.1 JSON bundle.
- Compatible with MISP, OpenCTI, and other STIX-consuming platforms.

---

## Testing

ForensIQ has **885 tests** across unit and integration layers.

### Run Tests

```bash
# Full suite with coverage
make test

# Unit tests only (fast, no external dependencies)
make test-unit

# Integration tests
make test-int

# All tests without coverage enforcement (development)
make test-fast

# Direct pytest invocation
python -m pytest tests/ -v
```

### Test Configuration

Configured in `pyproject.toml`:

- **Framework:** pytest with `asyncio_mode=auto`
- **Markers:** `unit`, `integration`, `slow`
- **Coverage:** CI enforces minimum 50% (`pyproject.toml`); `make test` enforces 90% for local development
- **Coverage source:** `src/forensiq/`

### Test Dependencies

```bash
pip install -e ".[dev]"
```

Includes: pytest, pytest-cov, pytest-asyncio, pytest-mock, respx (httpx mocking).

---

## Linting and Formatting

| Tool | Purpose | Command |
|---|---|---|
| **Ruff** | Linting + import sorting | `ruff check src/ tests/` |
| **Ruff** | Format check | `ruff format --check src/ tests/` |
| **MyPy** | Static type checking (strict) | `mypy src/` |
| **Black** | Code formatting | `black src/ tests/` |
| **Bandit** | Security audit | `bandit -r src/ -ll` |
| **pip-audit** | Dependency CVE audit | `pip-audit -r requirements.txt` |

### Quick Commands

```bash
make lint        # ruff check + mypy
make format      # black + ruff --fix
make security    # bandit security scan
```

### Ruff Configuration

- Line length: 100
- Target: Python 3.12
- Enabled rule sets: E, F, I, N, W, UP, B, S, A, C4, PTH, RUF
- Security rules (S) enabled; subprocess calls (S603, S607) ignored for Volatility 3 integration

### MyPy Configuration

- Strict mode enabled
- Pydantic plugin active
- Missing import stubs suppressed for: yara, xgboost, shap, joblib, sklearn, structlog, pandas, pefile, stix2

---

## Docker

> **Note:** Docker support is defined in the Makefile targets (`docker-up`, `docker-down`, `docker-pull`, `docker-build`) but the `docker/docker-compose.yml` and Dockerfile are not yet present in the repository. These targets are placeholders for planned Docker deployment with Ollama integration.

Planned Docker commands:

```bash
make docker-up       # Start ForensIQ + Ollama services
make docker-down     # Stop all services
make docker-pull     # Pull Mistral 7B into Ollama (~4.1 GB, first time)
make docker-build    # Build the ForensIQ Docker image
```

The intended setup runs ForensIQ alongside an Ollama container for local LLM inference, with the Ollama URL configured as `http://ollama:11434` within the compose network.

---

## CI/CD Pipeline

GitHub Actions workflow at `.github/workflows/ci.yml`:

### Jobs

| Job | Trigger | What It Does |
|---|---|---|
| **Lint & Type Check** | push to `main`/`develop`, PRs to `main` | Ruff lint, Ruff format check, MyPy strict |
| **Unit & Integration Tests** | After lint passes | Full test suite with coverage, uploads to Codecov |
| **Security Audit** | Parallel with tests | `pip-audit` for known CVEs in dependencies |

### Pipeline Flow

```
push/PR → Lint (ruff + mypy) → Tests (pytest + coverage) → Coverage upload
                            → Security (pip-audit)
```

---

## Security Considerations

### Built-in Security Features

- **XSS-safe HTML reports:** `_json_for_script` escapes `<`, `>`, `&` to prevent injection in report viewer.
- **LLM prompt injection prevention:** `_sanitize_token` strips braces and control characters from user-controllable data before LLM prompts.
- **Path traversal protection:** `_is_within_root` validates DLL paths before content hashing.
- **Cache file permissions:** Lockdown to `0o600` to prevent unauthorized read access.
- **SHA-256 validation:** All cache keys are SHA-256 hashed.
- **Plugin name sanitization:** Filesystem paths are sanitized to prevent directory traversal.

### Operational Security

- All analysis is performed **offline** by default.
- Threat intelligence (VT/MalwareBazaar) is **opt-in** and requires an explicit API key.
- No data is sent to external services unless the user explicitly configures API keys.
- The `.env` file is gitignored to prevent accidental credential exposure.

---

## Troubleshooting

### Common Issues

| Issue | Solution |
|---|---|
| `vol not found` | Install: `pip install volatility3` or set `FORENSIQ_VOLATILITY_PATH` |
| `yara-python compile error` | Install system library: `sudo apt-get install libyara-dev` (Debian) or `sudo pacman -S yara` (Arch) |
| `ML model not found` | Train: `forensiq train --data /path/to/dataset` or check `FORENSIQ_MODEL_PATH` |
| `Ollama not reachable` | Start: `ollama serve &` or use `--no-yara` to skip YARA generation |
| `Permission denied` on `/proc/kcore` | Run with `sudo` |
| LiME module not found | Build: `sudo forensiq live --build-lime` or install kernel headers |
| ISF symbol table missing | Build: `sudo forensiq live --build-isf` |
| Coverage below threshold | Add tests; current floor is 50%, target is 80% |

### Diagnostic Command

```bash
forensiq check
```

Verifies: Python version, Volatility 3, yara-python, ML model, Ollama connectivity, live memory capabilities.

### Debug Logging

```bash
forensiq analyze --dump /path/to/dump.raw --log-level DEBUG --log-format json
```

---

## Development

### Setup

```bash
make setup          # Install all dependencies
make check          # Verify components
```

### Available Make Targets

| Target | Description |
|---|---|
| `make setup` | Install all dependencies and configure environment |
| `make check` | Verify all required components are ready |
| `make analyze DUMP=/path/to/dump.raw` | Analyze a memory dump |
| `make analyze DUMP=/path/to/dump.raw OPTS='--no-yara'` | Analyze with custom options |
| `make train DATA=/path/to/dataset.parquet` | Train the ML model |
| `make download-data` | Download CIC-MalMem2022 dataset |
| `make test` | Full test suite with coverage (≥90% required) |
| `make test-unit` | Unit tests only |
| `make test-int` | Integration tests only |
| `make test-fast` | All tests without coverage enforcement |
| `make lint` | ruff + mypy |
| `make format` | black + ruff --fix |
| `make security` | bandit security scan |
| `make demo` | End-to-end demo with a public sample dump |
| `make docker-up` | Start Docker services |
| `make docker-down` | Stop Docker services |
| `make clean` | Remove generated files |

---

## Contributing

Contributions are welcome. Follow these steps:

### Reporting a Bug

1. Check [existing issues](https://github.com/Dacr2153/ForensIQ/issues) for duplicates.
2. Open an issue with:
   - ForensIQ version and system info (`forensiq version`).
   - Command executed and full output.
   - Logs (use `--log-level DEBUG --log-format json` if possible).
   - Description of expected vs. actual behavior.

### Submitting a Pull Request

1. **Fork** the repository and create a branch: `feature/my-change` or `fix/description`.
2. Ensure the code passes the full toolchain:

   ```bash
   make lint        # ruff + mypy
   make test-fast   # pytest without coverage
   make security    # bandit
   ```

3. Write tests for the change (if applicable) and update documentation.
4. Submit the PR against `main` describing the *what* and *why* of the change.

### Code Conventions

- Style: PEP 8, `snake_case` for functions/variables, `CamelCase` for classes.
- Complete type hints on all public interfaces (MyPy strict).
- Google-style docstrings for modules, classes, and public functions.
- No dead code: use `ruff`, `mypy`, and review unused imports.
- 100-character line limit (enforced by Ruff).

---

## License and Ethical Use

**MIT License** — see [LICENSE](https://opensource.org/licenses/MIT).

This tool is designed **exclusively** for **defensive forensics** on systems you own or have explicit written authorization to examine. Prohibited uses include:

- Analyzing systems without the owner's authorization.
- Evading security controls in production environments you do not own.
- Any activity that violates local or international cybersecurity laws.

> The author is not responsible for misuse of this tool. The user is responsible for complying with applicable legislation in their jurisdiction.

---

## Contact

| Resource | Link |
|---|---|
| Repository | [github.com/Dacr2153/ForensIQ](https://github.com/Dacr2153/ForensIQ) |
| Issues | [github.com/Dacr2153/ForensIQ/issues](https://github.com/Dacr2153/ForensIQ/issues) |
| CIC-MalMem2022 Dataset | [UNB CIC](https://www.unb.ca/cic/datasets/malmem-2022.html) |
| Volatility 3 | [volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3) |
| Ollama | [ollama.com](https://ollama.com) |
