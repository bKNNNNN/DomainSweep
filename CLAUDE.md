# CLAUDE.md - DomainSweep

> Guide for DomainSweep - Mass domain accessibility checker (6M+ domains)

## Project Overview

**Goal:** Check the accessibility of 6 million domains as fast as possible using a funnel approach:
1. DNS/MX validation → Filter dead domains
2. HTTP/HTTPS probing → Check web accessibility  
3. Cloudflare bypass → Handle protected sites

---

## Stack Technique

**YOU MUST use these tools (all open source/free):**

### DNS Resolution
| Priority | Tool | Use Case | Install |
|----------|------|----------|---------|
| 🥇 Primary | `dnsx` | MX/A record checks, wildcard filtering | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| 🥈 Fallback 1 | `massdns` | Raw speed (350k/sec) | `git clone https://github.com/blechschmidt/massdns && make` |
| 🥉 Fallback 2 | `zdns` | JSON output, reliable | `go install github.com/zmap/zdns@latest` |

### HTTP Probing
| Priority | Tool | Use Case | Install |
|----------|------|----------|---------|
| 🥇 Primary | `httpx` | Mass HTTP probing with tech detection | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| 🥈 Fallback 1 | `curl_cffi` | TLS fingerprint bypass | `pip install curl_cffi` |
| 🥉 Fallback 2 | `httprobe` | Lightweight alternative | `go install github.com/tomnomnom/httprobe@latest` |

### Cloudflare Bypass
| Priority | Tool | Use Case | Install |
|----------|------|----------|---------|
| 🥇 Primary | `curl_cffi` | TLS/JA3 fingerprint impersonation | `pip install curl_cffi` |
| 🥈 Fallback 1 | `FlareSolverr` | Headless browser solver | `docker pull flaresolverr/flaresolverr` |
| 🥉 Fallback 2 | `cloudscraper` | JS challenge solver | `pip install cloudscraper` |

### Data Processing
| Tool | Use Case | Install |
|------|----------|---------|
| `jq` | JSON processing | `apt install jq` |
| `csvkit` | CSV manipulation | `pip install csvkit` |
| `GNU parallel` | Parallel execution | `apt install parallel` |

### Infrastructure
| Tool | Use Case |
|------|----------|
| Docker | Container management |
| Python 3.11+ | Scripting |
| Go 1.21+ | Tool compilation |

---

## Pre-Commit Rules

**BEFORE ANY COMMIT TO GITHUB, YOU MUST:**
1. Run `/review-changes` to review all code modifications
2. Ensure all tests pass
3. Check that no sensitive data (API keys, passwords) is included
4. Verify documentation is updated if needed

---

## Infrastructure Recommendation

**⚠️ BEFORE RUNNING ANY SCAN SCRIPT, ALWAYS REMIND THE USER:**

```
🔒 INFRASTRUCTURE CHECK:
- ❌ Do NOT use a VPN (throttled bandwidth, unstable, DNS leaks)
- ✅ Use a dedicated VPS (Hetzner, OVH, Scaleway ~5€/month)
- ✅ Or use your local connection for small tests (< 10k domains)
- ✅ For Cloudflare bypass: consider residential proxies if needed
```

**Why no VPN?**
- VPN providers throttle high DNS/UDP traffic
- Shared IPs are often already flagged
- Connection drops cause scan failures
- See: [massdns Mullvad issue](https://github.com/projectdiscovery/dnsx/issues/221)

**Why not your home connection for large scans?**

Your ISP will likely flag unusual activity:
| Risk | Probability | Consequence |
|------|-------------|-------------|
| DNS throttling | 🔴 High | Requests become slow (rate limited) |
| Temp port 53 block | 🟠 Medium | No DNS resolution for a few hours |
| Warning email | 🟡 Low | "Unusual activity detected" |
| Service suspension | 🟢 Very low | Only for repeat offenders |

Rule of thumb:
- < 10k domains → Your connection is fine
- 10k-500k domains → Spread over several hours
- 500k+ domains → **Use a VPS** (safest option)

**TL;DR:** A VPS costs 4-5€/month and avoids all ISP issues. Your ISP only sees one encrypted SSH connection. No questions asked.

**Recommended setup for 6M domains:**
```bash
# Rent a cheap VPS with good bandwidth
# Example: Hetzner CX22 (2 vCPU, 4GB RAM, 40GB SSD) = ~4€/month

# Connect via SSH and run scripts there
ssh user@your-vps-ip
cd domain-checker
make run-all
```

---

## Code Guidelines

**IMPORTANT:** ALL code must be in English (variables, functions, comments, logs)

**YOU MUST:**
- Write modular scripts with clear separation of concerns
- Implement retry logic with exponential backoff
- Use streaming/chunked processing for large files (never load 6M lines in memory)
- Log progress and errors to separate files
- Support resume functionality for long-running tasks
- Output results in both JSON and CSV formats

**Naming Conventions:**
```
Scripts:      01_dns_check.py, 02_http_probe.py
Outputs:      results_dns_YYYYMMDD.json
Logs:         logs/dns_check_YYYYMMDD.log
Temp files:   tmp/chunk_001.txt
```

**Error Handling Pattern:**
```python
def process_domain(domain: str) -> dict:
    """Always return a dict with status, never raise exceptions"""
    try:
        # Primary tool
        result = primary_tool(domain)
    except Exception as e:
        try:
            # Fallback 1
            result = fallback_tool_1(domain)
        except Exception as e2:
            # Fallback 2 or error state
            result = {"domain": domain, "status": "error", "error": str(e2)}
    return result
```

---

## Architecture

```
input/
├── domains.txt              # 6M domains (one per line)
└── resolvers.txt            # DNS resolvers list

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

scripts/
├── 01_dns_check.py
├── 02_http_probe.py
├── 03_cloudflare_bypass.py
├── utils/
│   ├── chunker.py
│   ├── resolver.py
│   └── reporter.py
└── config.yaml

logs/
└── *.log
```

---

## Performance Targets

| Stage | Tool | Expected Speed | Time for 6M |
|-------|------|----------------|-------------|
| DNS Check | dnsx | ~50k/min | ~2 hours |
| HTTP Probe | httpx | ~30k/min | ~3-4 hours |
| CF Bypass | curl_cffi | ~5k/min | ~2-3 hours (subset) |

**Total estimated time:** 6-10 hours on a good VPS

---

## Configuration

**config.yaml:**
```yaml
# Threads and concurrency
dns_threads: 300
http_threads: 200
bypass_threads: 100

# Timeouts (seconds)
dns_timeout: 3
http_timeout: 5
bypass_timeout: 15

# Retry settings
max_retries: 3
retry_delay: 1

# Chunk size for processing
chunk_size: 100000

# Output formats
output_json: true
output_csv: true

# Cloudflare detection
cloudflare_indicators:
  - "cloudflare"
  - "cf-ray"
  - "challenge-platform"
```

---

## CLI Commands Reference

### DNS Check with dnsx
```bash
# MX records
cat domains.txt | dnsx -mx -silent -r resolvers.txt -t 300 -o mx_results.txt

# A records
cat domains.txt | dnsx -a -silent -r resolvers.txt -t 300 -resp -o a_results.txt

# Full recon
cat domains.txt | dnsx -recon -json -silent -t 300 -o full_dns.json
```

### DNS Check with massdns (fallback)
```bash
./bin/massdns -r resolvers.txt -t MX -o J domains.txt > mx_results.json
./bin/massdns -r resolvers.txt -t A -o J domains.txt > a_results.json
```

### HTTP Probe with httpx
```bash
cat domains.txt | httpx -silent -t 200 -timeout 5 \
    -status-code -title -tech-detect -cdn -json \
    -o http_results.json
```

### Cloudflare Bypass with curl_cffi
```python
from curl_cffi import requests
r = requests.get("https://example.com", impersonate="chrome", timeout=10)
```

---

## Errors to Avoid

### DNS Stage
- ❌ Don't use public resolvers without rate limiting → Use resolver rotation
- ❌ Don't trust single DNS response → Use multiple resolvers for validation
- ❌ Don't ignore NXDOMAIN → Log them separately for analysis

### HTTP Stage  
- ❌ Don't follow infinite redirects → Set max_redirects=5
- ❌ Don't ignore SSL errors silently → Log them with verify=False flag
- ❌ Don't hammer single IP → Implement per-IP rate limiting

### Cloudflare Bypass
- ❌ Don't use FlareSolverr for mass scanning → Too slow (2-5s/request)
- ❌ Don't expect 100% bypass rate → Accept 60-80% is realistic
- ❌ Don't run from datacenter IPs → Use residential proxies if needed

### General
- ❌ Don't load entire file in memory → Use generators and streaming
- ❌ Don't ignore keyboard interrupts → Implement graceful shutdown with state save
- ❌ Don't mix languages → Keep everything in English

---

## Testing Commands

```bash
# Test DNS setup
echo "google.com" | dnsx -a -silent

# Test HTTP setup
echo "https://google.com" | httpx -silent -status-code

# Test curl_cffi
python -c "from curl_cffi import requests; print(requests.get('https://httpbin.org/ip', impersonate='chrome').json())"

# Test FlareSolverr
curl -X POST http://localhost:8191/v1 -H "Content-Type: application/json" \
    -d '{"cmd":"request.get","url":"https://example.com","maxTimeout":60000}'
```

---

## Monitoring Progress

```bash
# Watch output file growth
watch -n 5 'wc -l output/*.txt'

# Monitor system resources
htop

# Check error logs
tail -f logs/*.log | grep -i error
```

---

## Workflow

- **Branch**: `<type>/<issue-number>-<description>` from `main`
- **Commit**: `<type>: <description>` (English, lowercase, max 72 chars)
- **PR**: Link with `Closes #XX`, squash merge, delete branch
- **Board**: Issues tracked in GitHub Project "claude-apps"
- **Labels**: `/setup-labels` to configure, `type/*` + `size/*` required per issue

---

*This file is part of Claude's prompt. Iterate and refine it as issues are encountered.*
*Press `#` during coding to add instructions automatically.*
