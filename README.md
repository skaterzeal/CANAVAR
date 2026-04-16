# Canavar Port Scanner v2026

> **Zero-dependency** cross-platform port scanner with live dashboard, vulnerability assessment, and stunning HTML reports.

**Platforms:** Windows · macOS · Kali Linux · Any Python 3.7+

---

## ⚠️ Legal Disclaimer — Read Before Use

**Canavar is a network reconnaissance tool intended for authorized security testing, internal network audits, and educational use only.**

- **Only scan systems you own or have explicit, written permission to test.** Scanning third-party systems without authorization is illegal in most jurisdictions (e.g., Computer Fraud and Abuse Act in the US, Computer Misuse Act in the UK, TCK 243/244 in Türkiye, and equivalent laws elsewhere) and may carry criminal and civil penalties.
- The vulnerability database is **indicative, not exhaustive** — it provides hints based on banner matching and a curated CVE list, and should not be treated as a substitute for a professional vulnerability assessment. Always verify findings against authoritative sources such as [NVD](https://nvd.nist.gov/) and the vendor's advisories.
- The author(s) and contributors of this project assume **no liability** for misuse, damage, or legal consequences arising from the use of this tool. By using Canavar, you accept full responsibility for your actions.
- For lawful testing targets, see [scanme.nmap.org](http://scanme.nmap.org) (explicitly allowed) or set up your own lab environment.

**If you are unsure whether you have authorization to scan a target, do not scan it.**

---

## Quick Start

```bash
# No installation needed! Just run:
python canavar.py -t 192.168.1.1 --top-ports 100

# Auto-scan your local network (no target needed!)
python canavar.py --auto --top-ports 100

# With live dashboard:
python canavar.py -t 10.0.0.0/24 --top-ports 50 --dashboard

# With vulnerability assessment:
python canavar.py -t target.com -p 22,80,443 --vuln-scan

# Optional: Install recommended packages for better experience
pip install tqdm colorama
```

> **Note:** The tool works with **zero pip dependencies**. All imports use Python standard library. `tqdm` and `colorama` are optional enhancements for progress bars and Windows colors.


## Features

### Core Scanning
- **Auto Local Network Scan** (`--auto`) – No target needed! Automatically detects your local subnet (default /24) and scans it. Host discovery is enabled automatically for fast results
- **TCP Connect Scan** – No root/admin required
- **SYN Stealth Scan** – Half-open scan (requires root + scapy)
- **UDP Scan** – Protocol-aware probes for DNS, SNMP, NTP, DHCP, TFTP
- **Multi-threaded** – 200 threads by default, scans 1000 ports in ~3-5 seconds
- **CIDR Support** – Scan entire subnets (e.g., `192.168.1.0/24`)
- **IPv6 Support** – Full IPv6 address and CIDR scanning (e.g., `::1`, `2001:db8::/64`). Large IPv6 CIDR ranges are automatically capped at 65,536 hosts for safety
- **Top Ports** – Scan most commonly open ports (`--top-ports 100`)

### Intelligence
- **CDN / Reverse Proxy Detection** – Automatically identifies when a target sits behind Cloudflare, Fastly, Akamai, CloudFront, Imperva, Sucuri, Azure Front Door, StackPath, EdgeCast, or CDN77. Uses a layered classifier (IP range membership + HTTP header fingerprints + port-set heuristic) with confidence scoring. CDN-hosted ports are clearly flagged in terminal, HTML, JSON, and CSV — with optional `--filter-cdn` to suppress CDN edge noise from the main report
- **Banner Grabbing** – Protocol-aware: HTTP, HTTPS, SSH, FTP, SMTP, POP3, IMAP, MySQL, Redis, MongoDB, Memcached, Elasticsearch, Telnet
- **CVE Suggestions** – Indicative CVE hints from a curated banner→CVE map. Not a substitute for a full vuln scanner; always verify against [NVD](https://nvd.nist.gov/)
- **NVD CVE Update** (`--update-cve`) – Optionally fetch latest CVEs from NVD API across ~24 keywords. Results cached locally for 24h and **persisted across runs** (subsequent scans automatically use cached data without re-fetching). Works fully offline with hardcoded CVEs when not used
- **Vulnerability Assessment** (`--vuln-scan`) – Version-aware checks against a small curated DB with CVSS scores and severity levels. Output is *indicative only* — confirm before remediation
- **OS Detection** (`--os-detect`) – TTL-based operating system fingerprinting (Linux/macOS/Windows/Network Device)
- **SSL/TLS Certificate Analysis** – Automatic certificate inspection on HTTPS ports: CN, Issuer, SAN, expiry date, days remaining

### Network & Performance
- **Host Discovery** (`--discovery`) – TCP and ICMP-based host discovery for CIDR ranges. Scans only alive hosts to save time
- **Timing Profiles** (`--timing 0-5`) – Nmap-style timing templates from Paranoid (T0) to Insane (T5)
- **Configurable Timeout** (`--timeout`) – Adjustable socket timeout for different network conditions
- **Retry Mechanism** (`--retries`) – Automatic retry for timed-out connections to reduce false negatives
- **Per-Port Latency** – Response time recorded for each open port in milliseconds

### Monitoring & Analysis
- **Live Web Dashboard** (`--dashboard`) – Real-time web dashboard at `localhost:8888` with SSE (Server-Sent Events). Watch ports being discovered as they happen with animated stats cards and live table updates
- **Scan Diff / Comparison** (`--diff`) – Compare current scan with a previous JSON export. Shows newly opened ports, closed ports, and changed banners with color-coded output

### Output & UX
- **Bilingual** – Turkish and English output (`--lang tr` / `--lang en`)
- **Reverse DNS** – Automatic hostname resolution for each target; shown in terminal and all reports
- **Auto-Versioned Filenames** – Each scan is saved with a unique filename (`canavar_<target>_<YYYYMMDD_HHMMSS>`) so previous scans are never overwritten
- **Custom Output Directory** (`--output-dir`) – Write all output files to a user-specified directory (created automatically if missing)
- **Export** – JSON (with full metadata), CSV, and stunning HTML reports with glassmorphism dark theme
- **Resizable HTML Columns** – Drag column edges in the HTML report to widen or shrink any column
- **Per-Target Summary Cards** – HTML report displays a card per target with hostname, IP, detected OS, and open-port count
- **Custom Logo** – Drop a `logo.png` in the project directory to brand your reports
- **Cross-Platform** – Windows, macOS, Kali Linux
- **Progress Bar** – Real-time tqdm progress with ETA

## Installation

```bash
pip install -r requirements.txt
```

For SYN scan support (optional):
```bash
pip install scapy
```

For logo resizing in reports (optional):
```bash
pip install Pillow
```

## Usage

### Auto Local Network Scan

Scan your own local network without specifying a target. Canavar detects your machine's primary IP, derives the subnet (default /24), and scans every host on it:

```bash
# Auto-scan local /24 network with top 100 ports
python canavar.py --auto --top-ports 100

# Auto-scan with vulnerability assessment + OS detection
python canavar.py --auto --top-ports 100 --vuln-scan --os-detect

# Auto-scan a /16 network (larger scope)
python canavar.py --auto --auto-prefix 16 --top-ports 50

# Auto-scan with live dashboard
python canavar.py --auto --top-ports 100 --dashboard --lang en
```

How it works:
1. Opens a UDP socket toward `8.8.8.8` (no packet leaves the host — just triggers OS routing decision) to discover this machine's outbound IP.
2. Falls back to hostname resolution if the UDP trick fails.
3. Constructs a CIDR subnet (`<your-ip>/<prefix>`) and enables `--discovery` automatically so only alive hosts are scanned.
4. Refuses to proceed if only the loopback interface is available.

> **⚠️ LEGAL NOTE:** `--auto` makes it trivially easy to scan the network you are connected to. **Only use this on networks you own or have explicit permission to test** (your home network, your lab, your employer's network with written authorization). Scanning a public Wi-Fi, hotel, or café network is almost certainly a legal violation. See the [Legal Disclaimer](#️-legal-disclaimer--read-before-use) above.

### Basic Scanning

```bash
# Basic scan (default: ports 1-1024)
python canavar.py -t 192.168.1.1

# Scan specific ports
python canavar.py -t example.com -p 22,80,443,8080

# Scan port range
python canavar.py -t 10.0.0.1 -p 1-65535 -th 500

# Top 100 most common ports
python canavar.py -t scanme.nmap.org --top-ports 100

# CIDR range scan
python canavar.py -t 192.168.1.0/24 -p 22,80,443

# SYN stealth scan (requires root/admin + scapy)
sudo python canavar.py -t 10.0.0.1 --syn --top-ports 50

# English output with custom filename
python canavar.py -t example.com --top-ports 100 --lang en -o my_report

# Fast scan without banners
python canavar.py -t 10.0.0.0/24 -p 22,80,443 --no-banner -th 300
```

### UDP Scanning

Scan UDP ports alongside TCP. Useful for discovering DNS, SNMP, NTP and other UDP-based services:

```bash
# UDP scan with default ports (53, 161, 123, 67, 68, 69)
python canavar.py -t 192.168.1.1 --udp

# UDP scan with custom ports
python canavar.py -t 10.0.0.1 --udp --udp-ports 53,161,500,1900

# Combined TCP + UDP scan
python canavar.py -t target.com -p 22,80,443 --udp --udp-ports 53,161
```

> **Note:** UDP scanning is inherently slower and less reliable than TCP. Ports that return a response are reported as `open`; silent ports are not listed since UDP cannot distinguish `open` from `filtered` without a reply. Protocol-specific probes are used for DNS, SNMP, NTP, DHCP, and TFTP to elicit responses.

### IPv6 Scanning

Full IPv6 support for all scan types:

```bash
# Scan IPv6 loopback
python canavar.py -t ::1 -p 22,80,443

# Scan IPv6 address
python canavar.py -t 2001:db8::1 --top-ports 50

# IPv6 with vulnerability scan
python canavar.py -t fe80::1 -p 22,80,443 --vuln-scan
```

> **Note:** IPv6 CIDR scanning is capped at the first 65,536 hosts to prevent infeasible scans on huge networks (e.g., a `/64` contains ~18 quintillion addresses).

### Timing Profiles

Control scan speed and stealth level with Nmap-style timing profiles:

```bash
# T0 - Paranoid: Very slow, 1 thread, 5s delay (IDS evasion)
python canavar.py -t target.com --top-ports 100 --timing 0

# T1 - Sneaky: Slow, 5 threads, 2s delay
python canavar.py -t target.com --top-ports 100 --timing 1

# T2 - Polite: Moderate, 10 threads, 0.5s delay
python canavar.py -t target.com --top-ports 100 --timing 2

# T3 - Normal: Default behavior, 200 threads (default)
python canavar.py -t target.com --top-ports 100 --timing 3

# T4 - Aggressive: Fast, 500 threads, 0.8s timeout
python canavar.py -t target.com --top-ports 100 --timing 4

# T5 - Insane: Maximum speed, 1000 threads, 0.5s timeout
python canavar.py -t target.com --top-ports 100 --timing 5
```

| Profile | Threads | Timeout | Delay | Use Case |
|---------|---------|---------|-------|----------|
| T0 Paranoid | 1 | 5.0s | 5.0s | IDS/IPS evasion |
| T1 Sneaky | 5 | 3.0s | 2.0s | Stealth scanning |
| T2 Polite | 10 | 2.0s | 0.5s | Bandwidth-limited networks |
| T3 Normal | 200 | 1.5s | 0s | Default general scanning |
| T4 Aggressive | 500 | 0.8s | 0s | Fast internal network scans |
| T5 Insane | 1000 | 0.5s | 0s | Maximum speed (stable networks) |

> **Note:** Timing profiles override `--threads` and `--timeout` values.

### Configurable Timeout

Adjust socket timeout for different network conditions:

```bash
# Slower timeout for high-latency networks
python canavar.py -t remote-server.com --top-ports 100 --timeout 3.0

# Faster timeout for local network
python canavar.py -t 192.168.1.1 --top-ports 100 --timeout 0.5
```

### Host Discovery

Discover alive hosts before port scanning. Essential for large CIDR ranges:

```bash
# Enable host discovery (TCP + ICMP ping)
python canavar.py -t 192.168.1.0/24 --top-ports 100 --discovery

# Force scan all hosts (skip discovery)
python canavar.py -t 10.0.0.0/24 --top-ports 50 --skip-discovery
```

Discovery uses TCP probes on ports 80, 443, 22, 21 and ICMP ping. Only alive hosts are scanned, saving significant time on large subnets.

### Retry Mechanism

Reduce false negatives on unstable networks:

```bash
# Retry timed-out connections 2 times
python canavar.py -t target.com -p 1-1024 --retries 2

# Combined with polite timing for unreliable networks
python canavar.py -t target.com --top-ports 200 --timing 2 --retries 3
```

### OS Detection

Detect target operating system based on TCP TTL analysis:

```bash
# Enable OS detection
python canavar.py -t 192.168.1.1 --top-ports 50 --os-detect

# Combine with full scan
python canavar.py -t target.com -p 1-1024 --os-detect --vuln-scan
```

Output example:
```
[OS] 192.168.1.1 → Linux/macOS (TTL: 64)
```

### SSL/TLS Certificate Analysis

Automatic certificate inspection on HTTPS ports (443, 8443, 4443, 9443):

```bash
# Certificate info is automatically included when scanning HTTPS ports
python canavar.py -t example.com -p 443,8443

# Combined with vulnerability assessment
python canavar.py -t target.com --top-ports 100 --vuln-scan
```

Reports include: Common Name (CN), Issuer, Subject Alternative Names (SAN), validity dates, and days until expiry. Expired or soon-to-expire certificates are flagged with warnings.

### CVE Database Update

Optionally fetch the latest CVEs from NIST NVD API:

```bash
# Update CVE database from NVD (uses free API, cached for 24 hours)
python canavar.py -t target.com --top-ports 100 --update-cve

# With NVD API key for higher rate limits (request at https://nvd.nist.gov/developers/request-an-api-key)
python canavar.py -t target.com --top-ports 100 --update-cve --nvd-api-key YOUR_API_KEY
```

> **Note:** This is completely optional. Without `--update-cve`, the tool uses its built-in CVE database. The NVD API requires no registration for basic use (5 requests per 30 seconds). An API key increases the limit to 50 requests per 30 seconds. Results are cached in `cve_cache.json` for 24 hours.

### Live Web Dashboard

Launch a real-time web dashboard that shows scan progress as it happens:

```bash
# Start scan with live dashboard (opens http://localhost:8888)
python canavar.py -t 192.168.1.0/24 --top-ports 100 --dashboard

# Custom dashboard port
python canavar.py -t 10.0.0.1 -p 1-1024 --dashboard --dashboard-port 9090
```

The dashboard provides:
- Real-time port discovery via Server-Sent Events (SSE)
- Live updating stats cards (scanned, open ports, elapsed, CVEs)
- Animated table that grows as ports are found
- Status indicator (SCANNING → COMPLETE)

### Vulnerability Assessment

Automatically detect vulnerable service versions from banners:

```bash
# Scan with vulnerability assessment
python canavar.py -t target.com --top-ports 100 --vuln-scan

# Combined with other features
python canavar.py -t 10.0.0.0/24 -p 22,80,443,3306,6379 --vuln-scan --lang en
```

Features:
- Parses service versions from banners (OpenSSH, Apache, nginx, MySQL, Redis, etc.)
- Checks against offline vulnerability database with version ranges
- Shows CVSS scores and severity levels (CRITICAL / HIGH / MEDIUM / LOW)
- Direct links to NVD for each CVE
- Results included in JSON/CSV/HTML exports

### CDN / Reverse Proxy Detection

When a target sits behind a CDN or reverse proxy (Cloudflare, Fastly, Akamai, CloudFront, Imperva, Sucuri, Azure Front Door, StackPath, EdgeCast, CDN77), the "open ports" you observe belong to the **CDN edge**, not the real origin server. Cloudflare alone responds on a fixed set of 13 ports for every hostname behind it — scanning a Cloudflare-protected site without awareness produces noisy, misleading reports where every target looks identical.

Canavar detects this automatically using three independent signals:

1. **IP range membership** — Every major CDN publishes its IP ranges. Canavar ships with a curated snapshot of ~400 CIDR blocks (Cloudflare, Fastly, Akamai, CloudFront, Imperva, Sucuri, Azure Front Door, StackPath) and can refresh them on demand from authoritative sources (`cloudflare.com/ips-v4`, Fastly public-ip-list API, AWS `ip-ranges.json`).
2. **HTTP header fingerprints** — 25+ regex signatures covering vendor-specific headers: `CF-RAY`, `CF-Cache-Status`, `X-Served-By: cache-*`, `X-Fastly-Request-ID`, `Server: AkamaiGHost`, `X-Amz-Cf-Id`, `X-Iinfo`, `X-Sucuri-ID`, `X-Azure-Ref`, and more. Run against already-grabbed banners — no extra requests.
3. **Edge-port heuristic** — When a target exposes the exact CDN-typical port set (80, 443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8080, 8443, 8880) without other signals, it's flagged as "Unknown CDN" at low confidence.

Findings carry a confidence level:
- **high** — both IP range and header signature match
- **medium** — one layer matches
- **low** — only the port-set heuristic matched

```bash
# Default: CDN-hosted ports are tagged but kept in the report
python canavar.py -t example.com --top-ports 100

# Filter: move CDN edge ports into a separate "cdn_filtered_ports" block in JSON
python canavar.py -t example.com --top-ports 100 --filter-cdn

# Refresh ranges from Cloudflare / Fastly / AWS (cached 7 days)
python canavar.py -t example.com --top-ports 100 --update-cdn-ranges
```

Output integration:
- **Terminal:** yellow `[!] CDN/Proxy detected: Cloudflare (confidence: high)` warning with up to 3 evidence lines
- **HTML:** dedicated "⚠ CDN / Reverse Proxy Detected" advisory card with per-target evidence; CDN column in the target table; `via <Provider>` badge on each affected port row
- **JSON:** `cdn_info` object per target (`is_cdn`, `provider`, `confidence`, `evidence`, `edge_ports_seen`); `via_cdn` and `cdn_provider` fields per port; when `--filter-cdn` is active, suppressed ports are preserved under `cdn_filtered_ports` (nothing is silently discarded)
- **CSV:** three additional columns: `CDN Provider`, `Via CDN`, `CDN Confidence`

> **To audit the real origin behind a CDN** you need to find the origin IP by other means — historical DNS (SecurityTrails, ViewDNS), certificate transparency logs (crt.sh), SPF record leaks, or direct vendor access. Canavar surfaces the problem; finding origins is out of scope.

### Scan Diff / Comparison

Compare two scans to detect changes over time:

```bash
# Step 1: Run initial scan
python canavar.py -t server.com --top-ports 100 -o baseline

# Step 2: Run again later and compare
python canavar.py -t server.com --top-ports 100 -o current --diff baseline.json
```

Output shows:
- **Newly opened ports** – Ports that weren't open before
- **Closed ports** – Ports that were open but are now closed
- **Changed banners** – Same port but different service banner (version update, etc.)

### Full Example: Comprehensive Scan

```bash
# Complete scan with all features enabled
python canavar.py -t 192.168.1.0/24 \
  --top-ports 100 \
  --discovery \
  --os-detect \
  --vuln-scan \
  --timing 3 \
  --retries 1 \
  --update-cve \
  --dashboard \
  --lang en \
  -o full_report
```

## CLI Arguments

| Argument | Description | Default |
|---|---|---|
| `-t, --target` | Target IP, hostname, IPv6, or CIDR | required unless `--auto` |
| `--auto` | Auto-detect local network and scan it (mutually exclusive with `-t`) | `false` |
| `--auto-prefix N` | CIDR prefix length used by `--auto` | `24` |
| `-p, --ports` | Port specification | `1-1024` |
| `--top-ports N` | Scan top N common ports | - |
| `-th, --threads` | Thread count (overridden by timing profile) | `200` |
| `--syn` | SYN stealth scan | `false` |
| `--udp` | Enable UDP scanning | `false` |
| `--udp-ports` | UDP ports to scan | `53,161,123,67,68,69` |
| `--no-banner` | Skip banner grabbing | `false` |
| `-o, --output` | Output filename prefix (default: `canavar_<target>_<timestamp>`) | auto |
| `--output-dir` | Directory where output files will be written (created if missing) | current dir |
| `--lang` | Language: `en` or `tr` | `tr` |
| `-v, --verbose` | Enable DEBUG-level logging (shows silent exceptions) | `false` |
| `--timeout` | Socket timeout in seconds | `1.5` |
| `--timing, -T` | Timing profile (0-5) | - |
| `--retries` | Retry count for failed connections | `0` |
| `--discovery` | Enable host discovery before scanning | `false` |
| `--skip-discovery` | Skip discovery, scan all CIDR hosts | `false` |
| `--os-detect` | Enable TTL-based OS detection | `false` |
| `--update-cve` | Update CVE database from NVD API | `false` |
| `--nvd-api-key` | NVD API key for higher rate limits | - |
| `--filter-cdn` | Suppress CDN/proxy edge ports from main report (kept in JSON for audit) | `false` |
| `--update-cdn-ranges` | Refresh CDN IP ranges from CF/Fastly/AWS (cached 7 days) | `false` |
| `--dashboard` | Launch live web dashboard | `false` |
| `--dashboard-port` | Dashboard port | `8888` |
| `--diff FILE` | Compare with previous scan JSON | - |
| `--vuln-scan` | Run vulnerability assessment | `false` |

## Output Files

By default, each scan generates three files named `canavar_<target>_<YYYYMMDD_HHMMSS>.{json,csv,html}` in the current directory — so previous scans are never overwritten. Use `-o` to set a custom prefix or `--output-dir` to redirect output to a specific folder.

- **`*.json`** – Machine-readable results with full metadata: per-target hostname, OS detection, latency, SSL cert info, and vulnerability data
- **`*.csv`** – Spreadsheet-compatible format including IP, hostname, and all scan fields
- **`*.html`** – Dark-themed interactive report with logo, per-target summary cards (hostname · IP · OS · open ports), resizable & sortable table, filter, SSL certificate cards, and latency stats

```bash
# Custom prefix
python canavar.py -t 192.168.1.1 --top-ports 100 -o my_scan

# Save all outputs to a directory
python canavar.py -t 192.168.1.0/24 --top-ports 100 --output-dir reports/

# Combine both
python canavar.py -t example.com -p 22,80,443 -o prod_audit --output-dir reports/weekly/
```

## License

MIT License – Use responsibly and only on networks you have permission to scan.
