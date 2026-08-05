#!/usr/bin/env bash
# FILE: scripts/download_datasets.sh
# ForensIQ — Dataset Acquisition Script
#
# CIC-MalMem2022 (Canadian Institute for Cybersecurity, University of New Brunswick)
# is the primary training dataset for the ForensIQ ML classifier.
#
# Dataset info:
#   - URL:     https://www.unb.ca/cic/datasets/malmem-2022.html
#   - Paper:   Nosouhi, M.R., et al. "CIC-MalMem-2022: A Benchmark Dataset for
#              Memory-Based Malware Detection" (2022)
#   - License: Research use — cite the paper if used in publications
#   - Size:    ~58,596 samples, 55 features per sample
#   - Classes: Benign, Spyware, Ransomware, Trojan, Backdoor
#
# ⚠ LEGAL NOTICE: This script downloads a publicly available research dataset.
# Do NOT download or store actual malware samples on unauthorized systems.
# The CIC-MalMem2022 dataset contains FEATURES extracted from memory dumps,
# NOT actual malware binaries. It is safe to download and use for research.
#
# Usage:
#   bash scripts/download_datasets.sh           # interactive
#   bash scripts/download_datasets.sh --dry-run # preview actions

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SCRIPT_NAME="$(basename -- "${BASH_SOURCE[0]}")"

# shellcheck source=./lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

DATA_DIR="ml/data"
DATASET_NAME="CIC-MalMem-2022"
DATASET_CSV="${DATA_DIR}/CIC-MalMem-2022.csv"

usage() {
    cat <<EOF
Usage: $SCRIPT_NAME [OPTIONS]

Options:
    --dry-run        Preview actions without changing anything
    -v, --verbose    Enable verbose/debug output
    -h, --help       Show this help message

The script is interactive: it offers instructions, a Kaggle CLI download
attempt, or verification of a CSV you already have.
EOF
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)  DRY_RUN=true; shift ;;
        -v|--verbose) VERBOSE=true; DEBUG=1; shift ;;
        -h|--help)  usage 0 ;;
        --)         shift; break ;;
        *)
            echo "ERROR: Unknown option: $1" >&2
            usage 1
            ;;
    esac
done

print_header() {
    echo ""
    echo -e "${C_BOLD}${C_CYAN}━━━ ForensIQ — Dataset Acquisition ━━━${C_NC}"
    echo ""
    echo -e "  Dataset: ${C_BOLD}CIC-MalMem-2022${C_NC}"
    echo -e "  Source:  University of New Brunswick — Canadian Institute for Cybersecurity"
    echo -e "  URL:     ${C_CYAN}https://www.unb.ca/cic/datasets/malmem-2022.html${C_NC}"
    echo ""
    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "  ${C_YELLOW}DRY-RUN MODE — no files will be changed.${C_NC}"
        echo ""
    fi
}

check_existing() {
    if ls "${DATA_DIR}"/*.csv &>/dev/null 2>&1; then
        log_ok "Dataset CSV files found in ${DATA_DIR}/"
        ls -lh "${DATA_DIR}"/*.csv
        echo ""
        if [[ "$DRY_RUN" == "true" ]]; then
            log_info "Dry-run: existing files would be kept."
            exit 0
        fi
        if ! confirm_prompt "Files already exist. Re-download? [y/N]"; then
            log_info "Using existing files."
            exit 0
        fi
    fi
}

download_instructions() {
    echo -e "${C_BOLD}How to obtain CIC-MalMem-2022:${C_NC}"
    echo ""
    echo -e "  ${C_BOLD}Option 1 — Official UNB Download (Recommended):${C_NC}"
    echo -e "    1. Visit: ${C_CYAN}https://www.unb.ca/cic/datasets/malmem-2022.html${C_NC}"
    echo -e "    2. Click 'Download Dataset' and fill in the access request form"
    echo -e "    3. You will receive a download link via email (usually within 24h)"
    echo -e "    4. Download the CSV file and place it in: ${C_CYAN}${DATA_DIR}/${C_NC}"
    echo ""
    echo -e "  ${C_BOLD}Option 2 — Kaggle Mirror (faster access):${C_NC}"
    echo -e "    Some researchers mirror this dataset on Kaggle:"
    echo -e "    ${C_CYAN}https://www.kaggle.com/datasets/search?q=CIC-MalMem-2022${C_NC}"
    echo ""
    echo -e "  ${C_BOLD}Option 3 — Direct Kaggle CLI download:${C_NC}"
    echo -e "    If you have the Kaggle CLI configured:"
    echo -e "    ${C_CYAN}pip install kaggle${C_NC}"
    echo -e "    ${C_CYAN}kaggle datasets download -d <dataset-slug> -p ${DATA_DIR}/${C_NC}"
    echo ""
    echo -e "  ${C_BOLD}Expected file name after download:${C_NC}"
    echo -e "    ${C_CYAN}${DATA_DIR}/CIC-MalMem-2022.csv${C_NC}"
    echo -e "    or any CSV with the 55-feature schema."
    echo ""
}

verify_dataset() {
    local -r csv_path="$1"
    log_info "Verifying dataset structure..."

    if [[ ! -f "$csv_path" ]]; then
        fatal "Dataset file not found: $csv_path"
    fi
    if [[ ! -s "$csv_path" ]]; then
        fatal "Dataset file is empty: $csv_path"
    fi

    # Check the CSV has the required columns
    REQUIRED_COLS=("Class" "pslist.nproc" "dlllist.ndlls" "malfind.ninjections" "handles.nhandles")
    local col
    for col in "${REQUIRED_COLS[@]}"; do
        if ! head -1 "$csv_path" | grep -q "$col"; then
            log_warn "Column '${col}' not found in CSV header."
            log_warn "This may not be the CIC-MalMem-2022 dataset, or it has a different format."
        fi
    done

    # Count rows
    ROW_COUNT=$(wc -l < "$csv_path")
    log_ok "CSV rows (including header): ${ROW_COUNT}"

    # Check class distribution
    log_info "Class distribution:"
    if command -v python3 &>/dev/null; then
        python3 - "$csv_path" << 'PYEOF'
import sys, csv
from collections import Counter
path = sys.argv[1]
classes = Counter()
with open(path) as f:
    reader = csv.DictReader(f)
    for row in reader:
        classes[row.get("Class", row.get("Category", "unknown"))] += 1
for cls, count in sorted(classes.items()):
    print(f"    {cls:20s}: {count:,}")
PYEOF
    fi
}

try_kaggle_download() {
    log_info "Attempting Kaggle CLI download..."

    if ! command -v kaggle &>/dev/null; then
        log_warn "Kaggle CLI not installed. Install with: pip install kaggle"
        return 1
    fi

    if [[ ! -f ~/.kaggle/kaggle.json ]]; then
        log_warn "Kaggle API credentials not found at ~/.kaggle/kaggle.json"
        log_warn "Get your API token from: https://www.kaggle.com/account"
        return 1
    fi

    # Try known mirrors
    local slugs=("rushilvarshney/cic-malmem-2022" "prasannjeet/cicmalmem2022")
    local slug
    for slug in "${slugs[@]}"; do
        log_info "Trying: kaggle datasets download -d ${slug}"
        if run_cmd kaggle datasets download -d "$slug" -p "$DATA_DIR" --unzip 2>/dev/null; then
            log_ok "Downloaded from Kaggle: ${slug}"
            return 0
        fi
    done

    log_warn "No Kaggle mirror found. Please download manually."
    return 1
}

interactive_setup() {
    # A `read` on a closed/non-interactive stdin returns non-zero and would
    # trip the ERR trap. Fail gracefully with the manual instructions instead.
    if [[ ! -t 0 ]]; then
        log_warn "No interactive terminal detected — cannot prompt for a download method."
        log_info "Place the dataset CSV at ${C_CYAN}${DATASET_CSV}${C_NC} then re-run,"
        log_info "or run this script from a terminal."
        download_instructions
        return 0
    fi

    echo ""
    echo -e "${C_BOLD}Choose an option:${C_NC}"
    echo "  1) Show download instructions (visit UNB website)"
    echo "  2) Try Kaggle CLI auto-download"
    echo "  3) I already have the CSV — just verify it"
    echo "  4) Exit"
    echo ""
    read -rp "Option [1-4]: " choice

    case "$choice" in
        1)
            download_instructions
            echo ""
            log_info "After downloading, place the CSV in ${C_CYAN}${DATA_DIR}/${C_NC}"
            log_info "Then re-run this script to verify the dataset."
            ;;
        2)
            if ! try_kaggle_download; then
                log_warn "Auto-download failed. Showing manual instructions..."
                download_instructions
            fi
            ;;
        3)
            echo ""
            read -rp "Path to your CSV file: " csv_path
            if [[ -f "$csv_path" ]]; then
                if [[ "$DRY_RUN" == "true" ]]; then
                    log_info "[DRY RUN] Would copy ${csv_path} → ${DATASET_CSV}"
                    verify_dataset "$csv_path"
                else
                    run_cmd cp "$csv_path" "$DATASET_CSV"
                    verify_dataset "$DATASET_CSV"
                    log_ok "Dataset ready at ${DATASET_CSV}"
                    log_info "Next step: make train DATA=ml/data/CIC-MalMem-2022.csv"
                fi
            else
                fatal "File not found: ${csv_path}"
            fi
            ;;
        4)
            exit 0
            ;;
        *)
            log_warn "Invalid option."
            ;;
    esac
}

main() {
    require_project_root

    check_dependencies python3
    ensure_directory "$DATA_DIR"

    print_header
    check_existing

    # Check if dataset already exists
    if [[ -f "$DATASET_CSV" ]]; then
        verify_dataset "$DATASET_CSV"
        echo ""
        log_ok "Dataset ready. Run: ${C_CYAN}make train DATA=ml/data/CIC-MalMem-2022.csv${C_NC}"
    elif [[ "$DRY_RUN" == "true" ]] && [[ ! -t 0 ]]; then
        log_info "[DRY RUN] Dataset missing — would open the interactive setup."
    else
        interactive_setup
    fi

    echo ""
    echo -e "  ${C_BOLD}Citation (if used in research):${C_NC}"
    echo -e "  Nosouhi, M.R., Mohammadi, S., Islam, R., Babar, M.A., et al. (2022)."
    echo -e "  'CIC-MalMem-2022: A Benchmark Dataset for Memory-Based Malware Detection'."
    echo -e "  Canadian Institute for Cybersecurity, University of New Brunswick."
    echo ""
}

main "$@"
