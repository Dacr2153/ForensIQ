#!/usr/bin/env bash
# FILE: scripts/demo.sh
# ForensIQ — End-to-End Demo Script
#
# Downloads a PUBLIC, LEGAL memory dump from MemLabs (educational CTF repository)
# and runs a complete ForensIQ analysis on it.
#
# MemLabs is a CTF memory forensics challenge repository by stuxnet999:
#   https://github.com/stuxnet999/MemLabs
# The challenge dumps are legal to download and use for educational/research purposes.
#
# Usage:
#   bash scripts/demo.sh                     # download + analyze the demo dump
#   bash scripts/demo.sh --dump /path.raw    # analyze your own dump
#   bash scripts/demo.sh --skip-download     # analyze already-downloaded dump
#   bash scripts/demo.sh --dry-run           # preview actions

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SCRIPT_NAME="$(basename -- "${BASH_SOURCE[0]}")"

# shellcheck source=./lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

# ─── Configuration ────────────────────────────────────────────────────────────
DEMO_DIR="./demo_dumps"
# MemLabs Challenge 1 — Windows XP/7 demo dump
# This is a well-known educational CTF dump, widely used in forensics training
DEMO_DUMP_URL="https://mega.nz/file/6l4BhKIb#l8ATZoliB_ULjvk9m_s4SQ9b1yhQ0OsXMYHMtIiSY5E"
DEMO_DUMP_NAME="MemLabs-Lab1.raw"
DEMO_DUMP_PATH="${DEMO_DIR}/${DEMO_DUMP_NAME}"
REPORT_PATH="./reports/demo_forensiq_report.html"

CUSTOM_DUMP=""
SKIP_DOWNLOAD=false
NO_OPEN=false

usage() {
    cat <<EOF
Usage: $SCRIPT_NAME [OPTIONS]

Options:
    --dump PATH         Analyze a specific memory dump instead of the demo one
    --skip-download     Skip the demo dump download (use existing file)
    --no-open           Do not try to open the report in a browser
    --dry-run           Preview actions without running the analysis
    -v, --verbose       Enable verbose/debug output
    -h, --help          Show this help message
EOF
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dump)         CUSTOM_DUMP="$2"; shift 2 ;;
        --dump=*)       CUSTOM_DUMP="${1#*=}"; shift ;;
        --skip-download) SKIP_DOWNLOAD=true; shift ;;
        --no-open)      NO_OPEN=true; shift ;;
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

print_header() {
    echo ""
    echo -e "${C_CYAN}${C_BOLD}"
    echo "  ╔═══════════════════════════════════════════════════╗"
    echo "  ║       ForensIQ — End-to-End Demo                 ║"
    echo "  ║  Memory Forensics & Threat Hunting Platform       ║"
    echo "  ╚═══════════════════════════════════════════════════╝"
    echo -e "${C_NC}"
    echo -e "  This demo analyzes a public educational CTF memory dump."
    echo -e "  Source: ${C_CYAN}https://github.com/stuxnet999/MemLabs${C_NC} (Lab 1)"
    echo -e "  Purpose: Educational demonstration — no real malware involved."
    echo ""
}

check_prerequisites() {
    log_step "Checking Prerequisites"
    local ok=true

    check_dependencies python3

    # Check forensiq is installed
    if python3 -c "from forensiq import __version__" 2>/dev/null; then
        log_ok "ForensIQ installed"
    else
        fatal "ForensIQ not installed. Run: make setup"
    fi

    # Check Volatility 3
    if python3 -c "import volatility3" 2>/dev/null; then
        log_ok "Volatility 3 available"
    else
        log_warn "Volatility 3 not found. Analysis will fail."
        ok=false
    fi

    # Check model
    if [[ -f "./ml/data/forensiq_model.joblib" ]]; then
        log_ok "ML model found"
    else
        log_warn "ML model not trained yet."
        log_warn "Classification scores will use heuristics only."
        log_warn "Train with: make train DATA=ml/data/<dataset>  (requires dataset download first)"
    fi

    # Check Ollama (optional for demo)
    if curl -sf --max-time 5 http://localhost:11434/api/tags &>/dev/null; then
        if ollama list 2>/dev/null | grep -q "mistral:7b"; then
            log_ok "Ollama + Mistral 7B available — YARA rules will be generated"
        else
            log_warn "Mistral 7B not available — skipping YARA generation in demo"
        fi
    else
        log_warn "Ollama not running — skipping YARA generation in demo"
    fi

    [[ "$ok" == "true" ]]
}

# validate_dump PATH — ensures the dump exists, is readable and non-trivial in size.
validate_dump() {
    local -r dump="$1"

    if [[ ! -f "$dump" ]]; then
        fatal "Memory dump not found: $dump"
    fi
    if [[ ! -r "$dump" ]]; then
        fatal "Memory dump is not readable: $dump"
    fi

    local -r size_bytes=$(stat -c %s "$dump" 2>/dev/null || stat -f %z "$dump" 2>/dev/null || echo 0)
    if [[ "$size_bytes" -lt 1048576 ]]; then
        log_warn "Dump is unusually small (${size_bytes} bytes) — this may not be a valid memory dump."
        if ! confirm_prompt "Continue anyway? [y/N]"; then
            exit 1
        fi
    fi

    log_ok "Dump validated: $dump ($(du -h "$dump" | cut -f1))"
}

download_demo_dump() {
    log_step "Downloading Demo Memory Dump"

    ensure_directory "$DEMO_DIR"

    if [[ -f "$DEMO_DUMP_PATH" ]]; then
        log_ok "Demo dump already downloaded: ${DEMO_DUMP_PATH}"
        log_info "Size: $(du -h "${DEMO_DUMP_PATH}" | cut -f1)"
        return 0
    fi

    if [[ "$SKIP_DOWNLOAD" == "true" ]]; then
        fatal "Demo dump not found at ${DEMO_DUMP_PATH} (and --skip-download was given)."
    fi

    echo ""
    echo -e "  The MemLabs Lab 1 challenge dump will be downloaded (~250 MB)."
    echo -e "  This is a public educational CTF dump — legal and safe to use."
    echo ""
    echo -e "  ${C_BOLD}Alternative options:${C_NC}"
    echo -e "    A) Provide your own dump: ${C_CYAN}make analyze DUMP=/path/to/your.raw${C_NC}"
    echo -e "    B) Download manually from: ${C_CYAN}https://github.com/stuxnet999/MemLabs${C_NC}"
    echo ""
    if ! confirm_prompt "Download MemLabs Lab 1 demo dump now? [Y/n]"; then
        echo ""
        log_warn "Demo cancelled. To analyze your own dump:"
        log_warn "  make analyze DUMP=/path/to/memory.raw"
        exit 0
    fi

    # Check for megadl (megatools) or suggest manual download
    if command -v megadl &>/dev/null; then
        log_info "Downloading via megadl..."
        run_cmd megadl "$DEMO_DUMP_URL" --path "$DEMO_DIR"
        log_ok "Download complete."
    else
        log_warn "megatools (megadl) not installed."
        log_warn "Install on Arch Linux: sudo pacman -S megatools"
        log_warn "Install on Debian: sudo apt-get install megatools"
        echo ""
        log_warn "Manual download:"
        log_warn "  1. Open: ${C_CYAN}${DEMO_DUMP_URL}${C_NC}"
        log_warn "  2. Download and place the file at: ${C_CYAN}${DEMO_DUMP_PATH}${C_NC}"
        log_warn "  3. Re-run: ${C_CYAN}bash scripts/demo.sh${C_NC}"
        echo ""
        log_warn "Or use your own memory dump:"
        log_warn "  make analyze DUMP=/path/to/memory.raw"
        exit 1
    fi

    # The demo file is downloaded before the analysis step; validate it.
    if [[ -f "$DEMO_DUMP_PATH" ]]; then
        validate_dump "$DEMO_DUMP_PATH"
    else
        log_warn "megadl did not produce ${DEMO_DUMP_PATH}."
        log_warn "The downloaded file may have a different name — check ${DEMO_DIR}/"
    fi
}

run_analysis() {
    log_step "Running ForensIQ Analysis"
    echo ""

    local dump_path="$CUSTOM_DUMP"
    if [[ -z "$dump_path" ]]; then
        dump_path="$DEMO_DUMP_PATH"
    fi
    validate_dump "$dump_path"

    log_info "Analyzing: ${C_CYAN}${dump_path}${C_NC}"
    log_info "Output:    ${C_CYAN}${REPORT_PATH}${C_NC}"
    echo ""

    # Determine YARA flag
    local -a yara_flags=()
    if ! curl -sf --max-time 5 http://localhost:11434/api/tags &>/dev/null; then
        yara_flags+=("--no-yara")
        log_info "Ollama not running — YARA generation disabled"
    fi

    # Run the analysis
    run_cmd python3 -m forensiq analyze \
        "$dump_path" \
        --output "$REPORT_PATH" \
        "${yara_flags[@]}"
}

open_report() {
    log_step "Opening Report"

    if [[ "$NO_OPEN" == "true" ]]; then
        log_info "Skipping browser open (--no-open)."
        return
    fi

    if [[ ! -f "$REPORT_PATH" ]]; then
        log_warn "Report not found at ${REPORT_PATH}"
        return
    fi

    log_ok "Report generated: ${REPORT_PATH}"
    log_info "File size: $(du -h "${REPORT_PATH}" | cut -f1)"

    # Try to open in browser
    if command -v xdg-open &>/dev/null; then
        log_info "Opening report in browser..."
        xdg-open "$(realpath "${REPORT_PATH}")" &>/dev/null &
    elif command -v firefox &>/dev/null; then
        firefox "$(realpath "${REPORT_PATH}")" &>/dev/null &
    else
        log_warn "Could not auto-open browser. Open manually:"
        log_warn "  ${C_CYAN}file://$(realpath "${REPORT_PATH}")${C_NC}"
    fi
}

main() {
    require_project_root

    # Activate venv if it exists
    if [[ -f ".venv/bin/activate" ]]; then
        # shellcheck source=/dev/null
        source .venv/bin/activate
    fi

    print_header
    check_prerequisites

    if [[ -n "$CUSTOM_DUMP" ]]; then
        log_info "Using custom dump: ${C_CYAN}${CUSTOM_DUMP}${C_NC}"
    else
        if [[ "$SKIP_DOWNLOAD" != "true" ]]; then
            download_demo_dump
        else
            log_warn "Skipping download (--skip-download)."
        fi
    fi

    run_analysis
    open_report

    echo ""
    echo -e "${C_GREEN}${C_BOLD}━━━ Demo Complete! ━━━${C_NC}"
    echo ""
    echo -e "  Report saved to: ${C_CYAN}${REPORT_PATH}${C_NC}"
    echo ""
    echo -e "  ${C_BOLD}Analyze your own dumps:${C_NC}"
    echo -e "    ${C_CYAN}make analyze DUMP=/path/to/memory.raw${C_NC}"
    echo -e "    ${C_CYAN}make analyze DUMP=/path/to/memory.raw OPTS='--verbose'${C_NC}"
    echo ""
}

main "$@"
