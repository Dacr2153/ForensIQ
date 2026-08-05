# FILE: Makefile
# ForensIQ — Memory Forensics & Threat Hunting Platform
# =======================================================
#
# QUICK START:
#   make setup                          # Install all dependencies
#   make check                          # Verify all components
#   make train DATA=/path/to/dataset    # Train the ML model
#   make analyze DUMP=/path/to/dump.raw # Analyze a memory dump
#   make test                           # Run test suite
#
# ⚠ For authorized forensic analysis only. Ethical use required.
# ─────────────────────────────────────────────────────────────────────────────

.DEFAULT_GOAL := help
.PHONY: help setup check analyze train test test-unit \
        test-int test-fast lint format security docker-up docker-down        \
        docker-pull docker-build demo download-data clean install install-dev

# ─── Variables ────────────────────────────────────────────────────────────────
PIP         := pip3
SRC         := src/forensiq
TESTS       := tests
REPORTS     := reports
YARA_RULES  := yara_rules
VENV        := .venv
VENV_PYTHON := $(VENV)/bin/python3

# Colors (GNU make >= 4.0)
RESET  := \033[0m
BOLD   := \033[1m
RED    := \033[0;31m
GREEN  := \033[0;32m
YELLOW := \033[1;33m
BLUE   := \033[0;34m
CYAN   := \033[0;36m

# ─── Help (default target) ────────────────────────────────────────────────────

## Display this help message
help:
	@printf "\n$(BOLD)$(CYAN)╔════════════════════════════════════════════════════════════╗$(RESET)\n"
	@printf "$(BOLD)$(CYAN)║   ForensIQ — Memory Forensics & Threat Hunting Platform   ║$(RESET)\n"
	@printf "$(BOLD)$(CYAN)╚════════════════════════════════════════════════════════════╝$(RESET)\n\n"
	@printf "$(YELLOW)⚠ For authorized forensic analysis only. Ethical use required.$(RESET)\n\n"
	@awk 'BEGIN {FS = ":.*?## "; section=""} \
	    /^##@/ { section = substr($$0, 5); printf "\n$(BOLD)$(GREEN)%s$(RESET)\n", section } \
	    /^[a-zA-Z_-]+:.*?## / { \
	        printf "  $(CYAN)%-22s$(RESET)%s\n", $$1, $$2 \
	    }' $(MAKEFILE_LIST)
	@echo ""
	@printf "$(BOLD)Examples:$(RESET)\n"
	@printf "  make analyze DUMP=/path/to/memory.raw\n"
	@printf "  make analyze DUMP=/path/to/memory.raw OPTS='--no-yara --verbose'\n\n"

##@ ─── Environment Setup ─────────────────────────────────────────────────────

setup: ## Install all dependencies and configure the environment (run first)
	@printf "$(BLUE)[*]$(RESET) Starting ForensIQ environment setup...\n"
	bash scripts/setup_env.sh

install: ## Install forensiq package (standard mode)
	@printf "$(BLUE)[*]$(RESET) Installing forensiq...\n"
	$(PIP) install -e .

install-dev: ## Install forensiq with development dependencies
	@printf "$(BLUE)[*]$(RESET) Installing forensiq [dev]...\n"
	$(PIP) install -e ".[dev]"

check: ## Verify all required components are ready (Volatility 3, Ollama, model)
	@printf "$(BLUE)[*]$(RESET) Checking ForensIQ components...\n"
	$(VENV_PYTHON) -m forensiq check

##@ ─── Memory Analysis ────────────────────────────────────────────────────────

analyze: ## Analyze a memory dump — REQUIRED: DUMP=/path/to/dump.raw
	@test -n "$(DUMP)" || \
	  (printf "$(RED)[✗]$(RESET) $(BOLD)Error:$(RESET) Specify dump path with $(CYAN)DUMP=/path/to/dump.raw$(RESET)\n\n" && \
	   printf "  Example: $(CYAN)make analyze DUMP=/path/to/memory.raw$(RESET)\n\n" && exit 1)
	$(VENV_PYTHON) -m forensiq analyze "$(DUMP)" $(OPTS)

##@ ─── Machine Learning ──────────────────────────────────────────────────────

download-data: ## Download CIC-MalMem2022 training dataset (see instructions)
	bash scripts/download_datasets.sh

train: ## Train the XGBoost classifier — REQUIRED: DATA=/path/to/dataset
	@test -n "$(DATA)" || \
	  (printf "$(RED)[✗]$(RESET) $(BOLD)Error:$(RESET) Specify dataset path with $(CYAN)DATA=/path/to/dataset.parquet$(RESET)\n\n" && \
	   printf "  Example: $(CYAN)make train DATA=ml/data/Obfuscated-MalMem2022.parquet$(RESET)\n\n" && exit 1)
	@printf "$(BLUE)[*]$(RESET) Training XGBoost classifier...\n"
	$(VENV_PYTHON) -m forensiq train --data "$(DATA)" $(OPTS)

##@ ─── Testing ────────────────────────────────────────────────────────────────

test: ## Run full test suite with coverage (≥90% required to pass)
	pytest $(TESTS)/ \
	  --cov=$(SRC) \
	  --cov-report=html:htmlcov \
	  --cov-report=term-missing \
	  --cov-fail-under=90

test-unit: ## Run unit tests only (fast, no external dependencies)
	pytest $(TESTS)/unit/ -v -m "unit or not integration"

test-int: ## Run integration tests (requires fixtures, no live Volatility/Ollama)
	pytest $(TESTS)/integration/ -v

test-fast: ## Run all tests without coverage enforcement (for development)
	pytest $(TESTS)/ -v --no-cov

##@ ─── Code Quality ───────────────────────────────────────────────────────────

lint: ## Run ruff linter and mypy type checker
	@printf "$(BLUE)[*]$(RESET) Running ruff...\n"
	ruff check $(SRC)/ $(TESTS)/
	@printf "$(BLUE)[*]$(RESET) Running mypy...\n"
	mypy $(SRC)/
	@printf "$(GREEN)[✓]$(RESET) Lint passed.\n"

format: ## Auto-format code with black and ruff --fix
	@printf "$(BLUE)[*]$(RESET) Formatting with black...\n"
	black $(SRC)/ $(TESTS)/
	@printf "$(BLUE)[*]$(RESET) Fixing imports with ruff...\n"
	ruff check --fix $(SRC)/

security: ## Run security audit with bandit (fails on HIGH/MEDIUM issues)
	@printf "$(BLUE)[*]$(RESET) Running bandit security scan...\n"
	bandit -r $(SRC)/ -ll -f txt
	@printf "$(GREEN)[✓]$(RESET) Security scan passed.\n"

##@ ─── Docker ─────────────────────────────────────────────────────────────────

docker-up: ## Start ForensIQ + Ollama services via Docker Compose
	@printf "$(BLUE)[*]$(RESET) Starting Docker services...\n"
	docker compose -f docker/docker-compose.yml up -d
	@printf "$(GREEN)[✓]$(RESET) Services started.\n"
	@printf "  Run $(CYAN)make docker-pull$(RESET) to download Mistral 7B (first time only).\n"

docker-down: ## Stop all Docker services
	docker compose -f docker/docker-compose.yml down

docker-pull: ## Pull Mistral 7B into Ollama container (~4.1 GB, first time only)
	@printf "$(BLUE)[*]$(RESET) Pulling Mistral 7B into Ollama container...\n"
	docker compose -f docker/docker-compose.yml exec ollama ollama pull mistral:7b

docker-build: ## Build the ForensIQ Docker image
	docker compose -f docker/docker-compose.yml build forensiq

##@ ─── Demo & Utilities ──────────────────────────────────────────────────────

demo: ## Run end-to-end demo with a public sample memory dump
	bash scripts/demo.sh

clean: ## Remove generated files (reports, YARA, caches, coverage)
	@printf "$(BLUE)[*]$(RESET) Cleaning generated files...\n"
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name .ruff_cache -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name htmlcov -exec rm -rf {} + 2>/dev/null || true
	@find . -name "*.pyc" -delete 2>/dev/null || true
	@find . -name ".coverage" -delete 2>/dev/null || true
	@rm -f $(REPORTS)/*.html $(REPORTS)/*.json
	@rm -f $(YARA_RULES)/*.yar $(YARA_RULES)/*.INVALID.txt
	@printf "$(GREEN)[✓]$(RESET) Clean complete.\n"
