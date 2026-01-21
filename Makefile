.PHONY: install install-go-tools install-python test clean run-dns run-http run-bypass run-all help

# Colors for output
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

# Default target
help:
	@echo "$(GREEN)Domain Accessibility Checker - Available commands:$(NC)"
	@echo ""
	@echo "  $(YELLOW)Setup:$(NC)"
	@echo "    make install          - Install all dependencies (Go tools + Python)"
	@echo "    make install-go-tools - Install Go tools only (dnsx, httpx, etc.)"
	@echo "    make install-python   - Install Python dependencies only"
	@echo ""
	@echo "  $(YELLOW)Run:$(NC)"
	@echo "    make run-dns          - Run DNS check (stage 1)"
	@echo "    make run-http         - Run HTTP probe (stage 2)"
	@echo "    make run-bypass       - Run Cloudflare bypass (stage 3)"
	@echo "    make run-all          - Run full pipeline"
	@echo ""
	@echo "  $(YELLOW)Utils:$(NC)"
	@echo "    make test             - Test all tools are installed"
	@echo "    make clean            - Clean temporary files"
	@echo "    make reset            - Reset all outputs (keep inputs)"
	@echo ""

# Full installation
install: install-go-tools install-python
	@echo "$(GREEN)✓ All dependencies installed$(NC)"

# Install Go tools
install-go-tools:
	@echo "$(YELLOW)Installing Go tools...$(NC)"
	@command -v go >/dev/null 2>&1 || { echo "$(RED)Error: Go is not installed. Please install Go 1.21+$(NC)"; exit 1; }
	go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
	go install github.com/projectdiscovery/httpx/cmd/httpx@latest
	go install github.com/tomnomnom/httprobe@latest
	go install github.com/zmap/zdns@latest || echo "$(YELLOW)Warning: zdns install failed, continuing...$(NC)"
	@echo "$(GREEN)✓ Go tools installed$(NC)"

# Install Python dependencies
install-python:
	@echo "$(YELLOW)Installing Python dependencies...$(NC)"
	@command -v python3 >/dev/null 2>&1 || { echo "$(RED)Error: Python 3 is not installed$(NC)"; exit 1; }
	pip install -r requirements.txt
	@echo "$(GREEN)✓ Python dependencies installed$(NC)"

# Test all tools
test:
	@echo "$(YELLOW)Testing installed tools...$(NC)"
	@echo ""
	@echo "DNS Tools:"
	@command -v dnsx >/dev/null 2>&1 && echo "  $(GREEN)✓ dnsx$(NC)" || echo "  $(RED)✗ dnsx not found$(NC)"
	@command -v zdns >/dev/null 2>&1 && echo "  $(GREEN)✓ zdns$(NC)" || echo "  $(YELLOW)○ zdns not found (optional)$(NC)"
	@echo ""
	@echo "HTTP Tools:"
	@command -v httpx >/dev/null 2>&1 && echo "  $(GREEN)✓ httpx$(NC)" || echo "  $(RED)✗ httpx not found$(NC)"
	@command -v httprobe >/dev/null 2>&1 && echo "  $(GREEN)✓ httprobe$(NC)" || echo "  $(YELLOW)○ httprobe not found (optional)$(NC)"
	@echo ""
	@echo "Python packages:"
	@python3 -c "import curl_cffi" 2>/dev/null && echo "  $(GREEN)✓ curl_cffi$(NC)" || echo "  $(RED)✗ curl_cffi not found$(NC)"
	@python3 -c "import yaml" 2>/dev/null && echo "  $(GREEN)✓ pyyaml$(NC)" || echo "  $(RED)✗ pyyaml not found$(NC)"
	@python3 -c "import tqdm" 2>/dev/null && echo "  $(GREEN)✓ tqdm$(NC)" || echo "  $(RED)✗ tqdm not found$(NC)"
	@echo ""
	@echo "Quick functional test:"
	@echo "google.com" | dnsx -a -silent >/dev/null 2>&1 && echo "  $(GREEN)✓ dnsx can resolve domains$(NC)" || echo "  $(RED)✗ dnsx test failed$(NC)"
	@echo "https://google.com" | httpx -silent -status-code 2>/dev/null | grep -q "200" && echo "  $(GREEN)✓ httpx can probe HTTP$(NC)" || echo "  $(RED)✗ httpx test failed$(NC)"

# Run DNS check
run-dns:
	@echo "$(YELLOW)Running DNS check...$(NC)"
	python3 scripts/01_dns_check.py

# Run HTTP probe
run-http:
	@echo "$(YELLOW)Running HTTP probe...$(NC)"
	python3 scripts/02_http_probe.py

# Run Cloudflare bypass
run-bypass:
	@echo "$(YELLOW)Running Cloudflare bypass...$(NC)"
	python3 scripts/03_cloudflare_bypass.py

# Run full pipeline
run-all:
	@echo "$(GREEN)========================================$(NC)"
	@echo "$(GREEN)  Domain Accessibility Checker$(NC)"
	@echo "$(GREEN)========================================$(NC)"
	@echo ""
	@echo "$(YELLOW)⚠️  INFRASTRUCTURE CHECK:$(NC)"
	@echo "  - ❌ Do NOT use a VPN (throttled bandwidth)"
	@echo "  - ✅ Use a dedicated VPS for large scans"
	@echo "  - ✅ Or local connection for < 10k domains"
	@echo ""
	@read -p "Press Enter to continue or Ctrl+C to abort..."
	@echo ""
	python3 scripts/run_pipeline.py

# Clean temporary files
clean:
	@echo "$(YELLOW)Cleaning temporary files...$(NC)"
	rm -rf tmp/*
	rm -rf __pycache__
	rm -rf scripts/__pycache__
	rm -rf scripts/utils/__pycache__
	find . -name "*.pyc" -delete
	find . -name ".DS_Store" -delete
	@echo "$(GREEN)✓ Cleaned$(NC)"

# Reset outputs (keep inputs)
reset:
	@echo "$(RED)This will delete all outputs. Are you sure?$(NC)"
	@read -p "Type 'yes' to confirm: " confirm && [ "$$confirm" = "yes" ] || exit 1
	rm -rf output/01_dns_results/*
	rm -rf output/02_http_results/*
	rm -rf output/03_bypass_results/*
	rm -rf output/final/*
	rm -rf logs/*
	@echo "$(GREEN)✓ Reset complete$(NC)"
