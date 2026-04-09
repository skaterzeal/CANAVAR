# Canavar Port Scanner v2026

> **Zero-dependency** cross-platform port scanner with live dashboard, vulnerability assessment, and stunning HTML reports.

**Platforms:** Windows · macOS · Kali Linux · Any Python 3.7+

## Quick Start

```bash
# No installation needed! Just run:
python canavar.py -t 192.168.1.1 --top-ports 100

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
- **TCP Connect Scan** – No root/admin required
- **SYN Stealth Scan** – Half-open scan (requires root + scapy)
- **UDP Scan** – Protocol-aware probes for DNS, SNMP, NTP, DHCP, TFTP
- **Multi-threaded** – 200 threads by default, scans 1000 ports in ~3-5 seconds
- **CIDR Support** – Scan entire subnets (e.g., `192.168.1.0/24`)
- **IPv6 Support** – Full IPv6 address and CIDR scanning (e.g., `::1`, `2001:db8::/64`). Large IPv6 CIDR ranges are automatically capped at 65,536 hosts for safety
- **Top Ports** – Scan most commonly open ports (`--top-ports 100`)

### Intelligence
- **Banner Grabbing** – Protocol-aware: HTTP, HTTPS, SSH, FTP, SMTP, POP3, IMAP, MySQL, Redis, MongoDB, Memcached, Elasticsearch, Telnet
- **CVE Suggestions** – Hardcoded real-world CVE matching based on banners
- **NVD CVE Update** (`--update-cve`) – Optionally fetch latest CVEs from NVD API. Results are cached locally for 24 hours. Works fully offline with hardcoded CVEs when not used
- **Vulnerability Assessment** (`--vuln-scan`) – Version-aware vulnerability detection with CVSS scores and severity levels
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
| `-t, --target` | Target IP, hostname, IPv6, or CIDR | *required* |
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
