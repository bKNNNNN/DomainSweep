# Domain Accessibility Checker

> Mass domain accessibility checker for 6M+ domains using a funnel approach.

## Overview

This tool checks domain accessibility through a 3-stage pipeline:

1. **DNS Check** - Filter dead domains (no MX/A records)
2. **HTTP Probe** - Check web accessibility, detect Cloudflare
3. **Cloudflare Bypass** - Handle protected sites with TLS fingerprint impersonation

## Quick Start

```bash
# 1. Install dependencies
make install

# 2. Test installation
make test

# 3. Add your domains
cp your_domains.txt input/domains.txt

# 4. Run the pipeline
make run-all
```

## Requirements

- **Go 1.21+** - For DNS/HTTP tools
- **Python 3.11+** - For scripting
- **Linux/macOS** - Primary support

## Installation

```bash
# Clone the repo
git clone <repo-url>
cd domain-checker

# Install everything
make install

# Or install separately
make install-go-tools  # dnsx, httpx, httprobe, zdns
make install-python    # Python packages
```

## Usage

### Full Pipeline

```bash
make run-all
```

### Individual Stages

```bash
# Stage 1: DNS Check
make run-dns

# Stage 2: HTTP Probe
make run-http

# Stage 3: Cloudflare Bypass
make run-bypass
```

### Configuration

Edit `config.yaml` to customize:
- Thread counts
- Timeouts
- Retry settings
- Output formats

## Infrastructure

⚠️ **For large scans (500k+ domains), use a VPS instead of your home connection.**

| Scale | Recommendation |
|-------|----------------|
| < 10k | Local connection OK |
| 10k-500k | Spread over hours |
| 500k+ | **Use a VPS** |

Recommended: Hetzner CX22 (~4€/month)

**Do NOT use a VPN** - They throttle DNS/UDP traffic.

## Output

```
output/
├── 01_dns_results/
│   ├── domains_with_mx.txt
│   ├── domains_with_a.txt
│   └── dns_errors.txt
├── 02_http_results/
│   ├── http_alive.json
│   ├── cloudflare_detected.txt
│   └── http_errors.txt
├── 03_bypass_results/
│   ├── bypass_success.json
│   └── bypass_failed.txt
└── final/
    ├── accessible_domains.csv
    └── full_report.json
```

## Performance

| Stage | Tool | Speed | Time for 6M |
|-------|------|-------|-------------|
| DNS | dnsx | ~50k/min | ~2h |
| HTTP | httpx | ~30k/min | ~3-4h |
| Bypass | curl_cffi | ~5k/min | ~2-3h* |

*Only for Cloudflare-detected subset

## Tools Used

| Category | Primary | Fallbacks |
|----------|---------|-----------|
| DNS | dnsx | massdns, zdns |
| HTTP | httpx | httprobe |
| Bypass | curl_cffi | FlareSolverr, cloudscraper |

## License

MIT
