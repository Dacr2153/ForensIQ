#!/usr/bin/env bash
# FILE: scripts/setup_env.sh
# ForensIQ — Complete Environment Setup Script
#
# Supports: Arch Linux, Debian/Ubuntu, Fedora/RHEL, openSUSE
# Tested on: Arch Linux (primary), Ubuntu 22.04+, Fedora 39+
#
# Usage:
#   bash scripts/setup_env.sh                     # interactive
#   bash scripts/setup_env.sh --skip-ollama        # skip Ollama step
#   bash scripts/setup_env.sh --skip-system        # skip system deps
#   bash scripts/setup_env.sh --dry-run            # preview changes only
#   bash scripts/setup_env.sh --help               # show options
#
# What this script does:
#   1. Installs system dependencies (yara library, build tools)
#   2. Creates Python virtual environment
#   3. Installs ForensIQ + all Python dependencies
#   4. Installs Volatility 3
#   5. Installs Ollama and downloads Mistral 7B (optional)
#   6. Creates required directories
#   7. Runs smoke tests to verify installation

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SCRIPT_NAME="$(basename -- "${BASH_SOURCE[0]}")"

# shellcheck source=./lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

# ─── Configuration ────────────────────────────────────────────────────────────
SKIP_SYSTEM=false
SKIP_OLLAMA=false
SKIP_SMOKE=false
NO_CONFIRM=false

usage() {
    cat <<EOF
Usage: $SCRIPT_NAME [OPTIONS]

Options:
    --skip-system       Skip system package installation (arch/deb/fedora/suse)
    --skip-ollama       Skip the Ollama + Mistral 7B step entirely
    --skip-smoke        Skip the final smoke tests
    --no-confirm        Do not ask for confirmation on unknown distros
    --dry-run           Print commands instead of executing them
    -v, --verbose       Enable verbose/debug output
    -h, --help          Show this help message

Examples:
    bash $SCRIPT_NAME --skip-ollama
    bash $SCRIPT_NAME --dry-run --skip-system
EOF
    exit "${1:-0}"
}

# Parse arguments (before any side effects)
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-system)  SKIP_SYSTEM=true; shift ;;
        --skip-ollama)  SKIP_OLLAMA=true; shift ;;
        --skip-smoke)   SKIP_SMOKE=true; shift ;;
        --no-confirm)   NO_CONFIRM=true; shift ;;
        --dry-run)      DRY_RUN=true; shift ;;
        -v|--verbose)   VERBOSE=true; DEBUG=1; shift ;;
        -h|--help)      usage 0 ;;
        --)             shift; break ;;
        *)
            echo "ERROR: Unknown option: $1" >&2
            usage 1
            ;;
    esac
done

# ─── Banner ───────────────────────────────────────────────────────────────────
print_banner() {
    echo -e "${C_CYAN}${C_BOLD}"
    cat << 'EOF'
  ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗
  ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔═══██╗
  █████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║   ██║
  ██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║▄▄ ██║
  ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╔╝
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚══▀▀═╝
EOF
    echo -e "${C_NC}"
    echo -e "${C_BOLD}  Memory Forensics & Threat Hunting Platform — Environment Setup${C_NC}"
    echo -e "  ${C_YELLOW}⚠ For authorized forensic analysis only — ethical use required${C_NC}"
    echo ""
    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "  ${C_YELLOW}DRY-RUN MODE — commands will be previewed, not executed.${C_NC}"
        echo ""
    fi
}

# ─── OS Detection ─────────────────────────────────────────────────────────────
detect_distro() {
    if [[ -f /etc/arch-release ]]; then
        echo "arch"
    elif [[ -f /etc/debian_version ]]; then
        echo "debian"
    elif [[ -f /etc/fedora-release ]]; then
        echo "fedora"
    elif [[ -f /etc/opensuse-release ]] || [[ -f /etc/SUSE-brand ]]; then
        echo "opensuse"
    else
        echo "unknown"
    fi
}

# ─── Step 1: System Dependencies ─────────────────────────────────────────────
install_system_deps() {
    local -r distro="$1"
    log_info "Installing system dependencies for: ${C_BOLD}${distro}${C_NC}"

    case "$distro" in
        arch)
            # yara: provides both the yara binary and the libyara shared library
            # base-devel: gcc, make, etc. needed to compile Python C extensions
            run_cmd sudo pacman -S --needed --noconfirm \
                python python-pip yara openssl libffi gcc base-devel git curl
            ;;
        debian)
            run_cmd sudo apt-get update -qq
            # libyara-dev: development headers for yara-python compilation
            run_cmd sudo apt-get install -y --no-install-recommends \
                python3 python3-pip python3-venv \
                libyara-dev libssl-dev libffi-dev \
                gcc make git curl build-essential
            ;;
        fedora)
            # yara-devel: development headers on Fedora
            run_cmd sudo dnf install -y --setopt=install_weak_deps=False \
                python3 python3-pip \
                yara yara-devel openssl-devel libffi-devel \
                gcc make git curl
            ;;
        opensuse)
            run_cmd sudo zypper install -y \
                python3 python3-pip \
                yara libyara-devel openssl-devel libffi-devel \
                gcc make git curl
            ;;
        *)
            log_warn "Unsupported/unknown distribution."
            log_warn "Please install manually BEFORE continuing:"
            log_warn "  - python 3.12+"
            log_warn "  - pip"
            log_warn "  - yara system library (yara / libyara-dev / yara-devel)"
            log_warn "  - openssl-dev, libffi-dev, gcc"
            if [[ "$NO_CONFIRM" != "true" ]] && ! confirm_prompt "Continue anyway? [y/N]"; then
                exit 1
            fi
            ;;
    esac

    log_ok "System dependencies installed."
}

# ─── Step 2: Python Virtual Environment ──────────────────────────────────────
setup_venv() {
    log_info "Setting up Python virtual environment (.venv)..."

    # Detect Python 3.12+
    PYTHON_CMD=""
    local version major minor
    for cmd in python3.12 python3 python; do
        if command -v "$cmd" &>/dev/null; then
            version="$("$cmd" --version 2>&1 | grep -oP '\d+\.\d+' | head -1)"
            major="${version%%.*}"
            minor="${version#*.}"
            if [[ "$major" -ge 3 ]] && [[ "$minor" -ge 12 ]]; then
                PYTHON_CMD="$cmd"
                break
            fi
        fi
    done

    if [[ -z "$PYTHON_CMD" ]]; then
        fatal "Python 3.12+ not found. Please install it and retry."
    fi

    log_info "Using Python: $("$PYTHON_CMD" --version)"

    if [[ ! -d ".venv" ]]; then
        run_cmd "$PYTHON_CMD" -m venv .venv
        log_ok "Virtual environment created at .venv/"
    else
        log_info ".venv already exists — skipping creation."
    fi

    # Activate and upgrade pip
    # shellcheck source=/dev/null
    source .venv/bin/activate
    run_cmd pip install --upgrade pip setuptools wheel -q
    log_ok "Virtual environment ready."
}

# ─── Step 3: ForensIQ Installation ───────────────────────────────────────────
install_forensiq() {
    log_info "Installing ForensIQ and all Python dependencies..."
    # shellcheck source=/dev/null
    source .venv/bin/activate

    # Install in editable mode with dev extras
    run_cmd pip install -e ".[dev]" --quiet

    log_ok "ForensIQ installed successfully."
}

# ─── Step 4: Volatility 3 ────────────────────────────────────────────────────
verify_volatility() {
    log_info "Verifying Volatility 3..."
    # shellcheck source=/dev/null
    source .venv/bin/activate

    # Volatility 3 is installed as a dependency of forensiq
    # but we verify the `vol` CLI is accessible
    if python3 -c "import volatility3" 2>/dev/null; then
        VOL_VERSION=$(python3 -c "import volatility3; print(volatility3.__version__)" 2>/dev/null || echo "unknown")
        log_ok "Volatility 3 v${VOL_VERSION} installed."
    else
        log_warn "volatility3 Python module not found. Installing..."
        run_cmd pip install volatility3 -q
    fi

    # Try to find the vol executable
    if command -v vol &>/dev/null; then
        log_ok "vol executable found at: $(command -v vol)"
    elif [[ -f ".venv/bin/vol" ]]; then
        log_ok "vol found at: .venv/bin/vol"
        log_warn "Activate venv before using: source .venv/bin/activate"
    else
        log_warn "vol not in PATH. Use the full path: .venv/bin/vol"
    fi
}

# ─── Step 5: Ollama ──────────────────────────────────────────────────────────
setup_ollama() {
    log_info "Checking Ollama installation..."

    if command -v ollama &>/dev/null; then
        log_ok "Ollama already installed: $(ollama --version 2>/dev/null || echo 'unknown version')"
    else
        log_info "Ollama not found. Installing..."
        log_info "Downloading Ollama installer from https://ollama.com/install.sh"

        if ! command -v curl &>/dev/null; then
            log_warn "curl not found. Install Ollama manually:"
            log_warn "  Arch Linux: yay -S ollama  or  paru -S ollama"
            log_warn "  Or visit:   https://ollama.com/download"
            return 0
        fi

        # Security: NEVER pipe a remote script straight into a shell. Download
        # to a temp file, verify it is non-empty, then execute from disk.
        local tmp_installer
        tmp_installer="$(mktemp /tmp/ollama-install.XXXXXX.sh)" || fatal "Failed to create temp installer"
        readonly tmp_installer
        register_temp_file "$tmp_installer"

        if ! curl -fSL --retry 3 --retry-delay 2 --connect-timeout 20 --max-time 300 \
            -o "$tmp_installer" https://ollama.com/install.sh; then
            rm -f -- "$tmp_installer" 2>/dev/null || true
            fatal "Failed to download Ollama installer."
        fi

        if [[ ! -s "$tmp_installer" ]]; then
            rm -f -- "$tmp_installer" 2>/dev/null || true
            fatal "Downloaded Ollama installer is empty."
        fi

        log_info "Verifying installer is a shell script..."
        if ! head -c 64 "$tmp_installer" | grep -qE '#!.*(sh|bash)'; then
            rm -f -- "$tmp_installer" 2>/dev/null || true
            fatal "Ollama installer is not a shell script — refusing to execute."
        fi

        run_cmd bash "$tmp_installer"
        log_ok "Ollama installed."
    fi

    # Ensure Ollama service is running
    if ! pgrep -x ollama &>/dev/null; then
        log_info "Starting Ollama server in background..."
        run_cmd nohup ollama serve > /tmp/ollama.log 2>&1 &
        log_info "Waiting for Ollama to start..."
        for _ in {1..10}; do
            if curl -sf --max-time 5 http://localhost:11434/api/tags &>/dev/null; then
                log_ok "Ollama server is running."
                break
            fi
            sleep 2
        done
    else
        log_ok "Ollama server already running."
    fi

    # Offer to pull Mistral 7B
    echo ""
    log_info "Mistral 7B is required for YARA rule generation (~4.1 GB download)."
    if ollama list 2>/dev/null | grep -q "mistral:7b"; then
        log_ok "Mistral 7B is already available."
    else
        if [[ "$NO_CONFIRM" == "true" ]] || confirm_prompt "Download Mistral 7B now? [Y/n]"; then
            log_info "Pulling Mistral 7B (this may take several minutes)..."
            run_cmd ollama pull mistral:7b
            log_ok "Mistral 7B downloaded and ready."
        else
            log_warn "Skipped. Run later: ollama pull mistral:7b"
            log_warn "YARA generation will fail until Mistral 7B is available."
        fi
    fi
}

# ─── Step 6: Directory Structure & Config ────────────────────────────────────
setup_directories() {
    log_info "Creating required directories..."
    ensure_directory reports
    ensure_directory yara_rules
    ensure_directory ml/data
    log_ok "Directories ready: reports/ yara_rules/ ml/data/"
}

setup_env_file() {
    if [[ ! -f ".env" ]]; then
        log_info "Creating .env from .env.example..."
        run_cmd cp .env.example .env
        log_ok ".env created. Review settings: ${C_CYAN}nano .env${C_NC}"

        # Auto-detect vol path and update .env (only if not already set)
        if command -v vol &>/dev/null; then
            VOL_PATH=$(command -v vol)
            run_cmd sed -i "s|FORENSIQ_VOLATILITY_PATH=vol|FORENSIQ_VOLATILITY_PATH=${VOL_PATH}|" .env
            log_ok "FORENSIQ_VOLATILITY_PATH set to: ${VOL_PATH}"
        elif [[ -f ".venv/bin/vol" ]]; then
            ABS_VOL=$(realpath .venv/bin/vol)
            run_cmd sed -i "s|FORENSIQ_VOLATILITY_PATH=vol|FORENSIQ_VOLATILITY_PATH=${ABS_VOL}|" .env
            log_ok "FORENSIQ_VOLATILITY_PATH set to: ${ABS_VOL}"
        fi
    else
        log_warn ".env already exists — not overwriting. Review manually if needed."
    fi
}

# ─── Step 7: Smoke Tests ─────────────────────────────────────────────────────
run_smoke_tests() {
    log_step "Smoke Tests"
    # shellcheck source=/dev/null
    source .venv/bin/activate

    local all_ok=true

    # Python version
    PY_VER=$(python3 --version 2>&1)
    log_ok "Python: ${PY_VER}"

    # yara-python
    if python3 -c "import yara; print(yara.__version__)" &>/dev/null; then
        YARA_VER=$(python3 -c "import yara; print(yara.__version__)" 2>/dev/null)
        log_ok "yara-python: v${YARA_VER}"
    else
        log_warn "yara-python import FAILED."
        log_warn "Fix: ensure libyara system library is installed, then: pip install yara-python"
        all_ok=false
    fi

    # Volatility 3
    if python3 -c "import volatility3" &>/dev/null; then
        VOL_VER=$(python3 -c "import volatility3; print(volatility3.__version__)" 2>/dev/null)
        log_ok "Volatility 3: v${VOL_VER}"
    else
        log_warn "Volatility 3 import FAILED."
        all_ok=false
    fi

    # Ollama
    if curl -sf --max-time 5 http://localhost:11434/api/tags &>/dev/null; then
        log_ok "Ollama API: reachable at http://localhost:11434"
        if ollama list 2>/dev/null | grep -q "mistral:7b"; then
            log_ok "Mistral 7B: available"
        else
            log_warn "Mistral 7B: not pulled yet. Run: ollama pull mistral:7b"
        fi
    else
        log_warn "Ollama: not reachable. YARA generation disabled until started."
        log_warn "Start with: ollama serve"
    fi

    # ForensIQ package
    if python3 -c "from forensiq import __version__; print(__version__)" &>/dev/null; then
        FORENSIQ_VER=$(python3 -c "from forensiq import __version__; print(__version__)" 2>/dev/null)
        log_ok "ForensIQ: v${FORENSIQ_VER}"
    else
        log_warn "ForensIQ package not importable. Check installation."
        all_ok=false
    fi

    echo ""
    if [[ "$all_ok" == "true" ]]; then
        log_ok "All core components ready!"
    else
        log_warn "Some components need attention. Review warnings above."
        log_warn "Re-run 'make check' after fixing issues."
    fi
}

# ─── Main ─────────────────────────────────────────────────────────────────────
main() {
    require_project_root

    print_banner

    local distro
    distro=$(detect_distro)
    log_info "Detected distribution: ${C_BOLD}${distro}${C_NC}"

    log_step "Step 1/6 — System Dependencies"
    if [[ "$SKIP_SYSTEM" == "true" ]]; then
        log_warn "Skipping system dependency installation (--skip-system)."
    else
        install_system_deps "$distro"
    fi

    log_step "Step 2/6 — Python Virtual Environment"
    setup_venv

    log_step "Step 3/6 — ForensIQ Package"
    install_forensiq

    log_step "Step 4/6 — Volatility 3 Verification"
    verify_volatility

    log_step "Step 5/6 — Ollama + Mistral 7B"
    if [[ "$SKIP_OLLAMA" == "true" ]]; then
        log_warn "Skipping Ollama setup (--skip-ollama)."
    else
        setup_ollama
    fi

    log_step "Step 6/6 — Directories & Configuration"
    setup_directories
    setup_env_file

    if [[ "$SKIP_SMOKE" != "true" ]]; then
        run_smoke_tests
    fi

    echo ""
    echo -e "${C_GREEN}${C_BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_NC}"
    echo -e "${C_GREEN}${C_BOLD}  ForensIQ Environment Setup Complete!${C_NC}"
    echo -e "${C_GREEN}${C_BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_NC}"
    echo ""
    echo -e "  ${C_BOLD}Next Steps:${C_NC}"
    echo -e "    1. Activate venv:     ${C_CYAN}source .venv/bin/activate${C_NC}"
    echo -e "    2. Full check:        ${C_CYAN}make check${C_NC}"
    echo -e "    3. Download dataset:  ${C_CYAN}make download-data${C_NC}"
    echo -e "    4. Train model:       ${C_CYAN}make train DATA=ml/data/<dataset>.parquet${C_NC}"
    echo -e "    5. Run demo:          ${C_CYAN}make demo${C_NC}"
    echo -e "    6. Analyze a dump:    ${C_CYAN}make analyze DUMP=/path/to/memory.raw${C_NC}"
    echo ""
    echo -e "  ${C_YELLOW}⚠ Only analyze memory dumps you own or have written authorization for.${C_NC}"
    echo ""
}

main "$@"
