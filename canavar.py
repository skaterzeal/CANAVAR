#!/usr/bin/env python3
"""
Canavar Port Scanner v2026
Cross-platform network reconnaissance tool.
Supports TCP Connect & SYN scan, UDP scan, banner grabbing, CVE suggestions,
CIDR ranges, multi-threading, OS detection, SSL analysis, and beautiful HTML/JSON/CSV reports.
"""

import socket
import threading
from queue import Queue
import time
import json
import csv
import os
import sys
import ssl
import re
import platform
import argparse
import ipaddress
import base64
import webbrowser
import subprocess
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from datetime import datetime, timedelta
from html import escape as html_escape
import email.utils
import logging

# Configure logging
logger = logging.getLogger("canavar")

# ── Optional Dependencies ──────────────────────────────────────
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

try:
    import colorama
    colorama.init(autoreset=False)
except ImportError:
    if platform.system() == "Windows":
        os.system("")  # Enable ANSI on Windows 10+

HAS_SCAPY = False
try:
    from scapy.all import IP, TCP, sr1, send, conf
    conf.verb = 0
    HAS_SCAPY = True
except ImportError:
    pass

# ── Logo Handling ──────────────────────────────────────────────
def _get_script_dir():
    return os.path.dirname(os.path.abspath(__file__))

_logo_cache = {}

def get_logo_base64(max_size=200):
    """Load logo.png from script directory and return base64 string.
    Result is cached per max_size to avoid re-encoding.
    Attempts to resize with Pillow; falls back to raw file."""
    if max_size in _logo_cache:
        return _logo_cache[max_size]
    logo_path = os.path.join(_get_script_dir(), "logo.png")
    if not os.path.exists(logo_path):
        _logo_cache[max_size] = ""
        return ""
    try:
        from PIL import Image
        import io
        img = Image.open(logo_path)
        img = img.resize((max_size, max_size), Image.LANCZOS)
        if img.mode != "RGBA":
            img = img.convert("RGBA")
        buf = io.BytesIO()
        img.save(buf, format="PNG", optimize=True)
        result = base64.b64encode(buf.getvalue()).decode()
    except ImportError:
        # No Pillow – embed raw (may be large)
        try:
            with open(logo_path, "rb") as f:
                result = base64.b64encode(f.read()).decode()
        except Exception:
            result = ""
    except Exception:
        result = ""
    _logo_cache[max_size] = result
    return result

# ── ASCII Banner ───────────────────────────────────────────────
BANNER_ART = r"""
   ____
  / ___|__ _ _ __   __ ___   ____ _ _ __
 | |   / _` | '_ \ / _` \ \ / / _` | '__|
 | |__| (_| | | | | (_| |\ V / (_| | |
  \____\__,_|_| |_|\__,_| \_/ \__,_|_|
        Port Scanner v2026 | Cross-Platform
"""

# ── Language System ────────────────────────────────────────────
LANG = {
    "en": {
        "scan_started": "SCAN STARTED → {target} ({time})",
        "scan_finished": "SCAN FINISHED! {count} open port(s) found ({elapsed}s)",
        "results_saved": "Results saved: {files}",
        "port_open": "Port {port:<5} OPEN ({stype}) | {service:<12} | {banner}",
        "cve_hint": " ⚠ CVE: {cves}",
        "no_banner": "No banner",
        "scanning_target": "== Scanning: {target} ==",
        "cidr_info": "CIDR range: {count} host(s) to scan",
        "syn_no_scapy": "[!] Scapy not installed. Falling back to TCP Connect.",
        "syn_no_root": "[!] SYN scan needs root/admin. Falling back to TCP Connect.",
        "error": "Error: {msg}",
        "html_saved": "HTML report saved: {file}",
        "interrupted": "\n[!] Scan interrupted. Saving partial results...",
        "progress": "Scanning",
        "report_title": "Port Scan Report",
        "target": "Target",
        "ports_scanned": "Ports Scanned",
        "open_ports": "Open Ports",
        "scan_type": "Scan Type",
        "duration": "Duration",
        "port": "Port",
        "service": "Service",
        "banner": "Banner",
        "cve": "CVE Suggestions",
        "status": "Status",
        "generated": "Generated",
        "no_open": "No open ports found.",
        "udp_scan": "UDP Scan",
        "os_detect": "OS Detection",
        "timing_profile": "Timing Profile",
        "host_discovery": "Host Discovery",
        "discovery_result": "Discovered {alive}/{total} host(s)",
        "retry_info": "Retries",
        "cert_info": "SSL Certificate",
        "cert_expired": "Expired",
        "cert_expiring": "Expiring soon",
        "updating_cve": "Updating CVE database from NVD",
        "cve_updated": "CVE database updated",
        "cve_update_failed": "CVE update failed, using cache",
        "latency": "Latency",
        "avg_latency": "AVG Latency",
        "ssl_cert": "SSL Cert",
        "scan_comparison": "SCAN COMPARISON (previous: {prev_time})",
        "new_open_ports": "Newly Opened Ports",
        "closed_ports_label": "Closed Ports",
        "changed_banners": "Changed Banners",
        "no_changes": "No changes detected.",
        "vuln_assessment": "VULNERABILITY ASSESSMENT",
        "no_vuln_found": "No version-based vulnerabilities found.",
    },
    "tr": {
        "scan_started": "TARAMA BAŞLADI → {target} ({time})",
        "scan_finished": "TARAMA BİTTİ! {count} açık port bulundu ({elapsed}s)",
        "results_saved": "Sonuçlar kaydedildi: {files}",
        "port_open": "Port {port:<5} AÇIK ({stype}) | {service:<12} | {banner}",
        "cve_hint": " ⚠ CVE: {cves}",
        "no_banner": "Banner yok",
        "scanning_target": "== Hedef: {target} ==",
        "cidr_info": "CIDR aralığı: {count} host taranacak",
        "syn_no_scapy": "[!] Scapy yüklü değil. TCP Connect'e geçiliyor.",
        "syn_no_root": "[!] SYN scan root/admin gerektirir. TCP Connect'e geçiliyor.",
        "error": "Hata: {msg}",
        "html_saved": "HTML rapor kaydedildi: {file}",
        "interrupted": "\n[!] Tarama kesildi. Kısmi sonuçlar kaydediliyor...",
        "progress": "Taranıyor",
        "report_title": "Port Tarama Raporu",
        "target": "Hedef",
        "ports_scanned": "Taranan Portlar",
        "open_ports": "Açık Portlar",
        "scan_type": "Tarama Tipi",
        "duration": "Süre",
        "port": "Port",
        "service": "Servis",
        "banner": "Banner",
        "cve": "CVE Önerileri",
        "status": "Durum",
        "generated": "Oluşturulma",
        "no_open": "Açık port bulunamadı.",
        "udp_scan": "UDP Taraması",
        "os_detect": "İşletim Sistemi Algılama",
        "timing_profile": "Zamanlama Profili",
        "host_discovery": "Ana Bilgisayar Keşfi",
        "discovery_result": "{alive}/{total} ana bilgisayar bulundu",
        "retry_info": "Yeniden Denemeler",
        "cert_info": "SSL Sertifikası",
        "cert_expired": "Süresi Doldu",
        "cert_expiring": "Yakında Sona Erecek",
        "updating_cve": "CVE veritabanı NVD'den güncelleniyor",
        "cve_updated": "CVE veritabanı güncellendi",
        "cve_update_failed": "CVE güncellemesi başarısız, önbellek kullanılıyor",
        "latency": "Gecikme",
        "avg_latency": "ORT Gecikme",
        "ssl_cert": "SSL Sertifika",
        "scan_comparison": "TARAMA KARŞILAŞTIRMASI (önceki: {prev_time})",
        "new_open_ports": "Yeni Açık Portlar",
        "closed_ports_label": "Kapanan Portlar",
        "changed_banners": "Değişen Banner'lar",
        "no_changes": "Değişiklik yok.",
        "vuln_assessment": "ZAFİYET DEĞERLENDİRMESİ",
        "no_vuln_found": "Versiyon bazlı zafiyet bulunamadı.",
    },
}

# ── Top Ports (sorted by frequency, Nmap data) ────────────────
TOP_PORTS = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135,
    3306, 8080, 1723, 111, 995, 993, 5900, 1025, 587, 8888, 199,
    1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026,
    2000, 8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515,
    8008, 49154, 1027, 5666, 646, 5000, 5631, 631, 49153, 8081,
    2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990,
    5357, 427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128,
    444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986, 13,
    1029, 9, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100,
    119, 37, 1000, 3001, 5001, 82, 10010, 1030, 9090, 2107,
    1024, 2103, 6004, 1801, 5050, 19, 8031, 1041, 255, 2967,
    1049, 1048, 1053, 1054, 1056, 1064, 3703, 17, 808, 3689,
    1031, 1044, 1071, 5901, 9102, 100, 8010, 2869, 1039, 5120,
    4001, 9000, 2105, 636, 1038, 2601, 7000, 1, 2604,
    9800, 2602, 7443, 1068, 6002, 2605, 6003, 9801, 5002, 9802,
    1058, 1059, 1060, 1062, 1063, 1065, 1066, 1069, 1070,
    8028, 2222, 4444, 3283, 1080, 8291, 9001, 18080, 8082, 8083,
    8084, 8085, 8086, 8087, 8088, 8089, 27017, 6379, 11211,
    9200, 9300, 5601, 8200, 4443, 8880, 2383, 2381, 1434,
]
# Deduplicate while preserving order
_seen = set()
TOP_PORTS = [p for p in TOP_PORTS if not (p in _seen or _seen.add(p))]

# ── Well-Known Ports ───────────────────────────────────────────
WELL_KNOWN_PORTS = {
    1: "TCPMUX", 7: "Echo", 9: "Discard", 13: "Daytime", 17: "QOTD",
    19: "Chargen", 20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 26: "SMTP-Alt", 37: "Time", 53: "DNS", 67: "DHCP",
    69: "TFTP", 79: "Finger", 80: "HTTP", 81: "HTTP-Alt", 82: "HTTP-Alt",
    88: "Kerberos", 100: "NewACCT", 106: "poppassd", 110: "POP3",
    111: "RPCbind", 113: "IDENT", 119: "NNTP", 123: "NTP", 135: "MSRPC",
    137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
    143: "IMAP", 144: "NeWS", 161: "SNMP", 179: "BGP", 199: "SMUX",
    255: "Novadigm", 389: "LDAP", 427: "SLP", 443: "HTTPS",
    444: "SNPP", 445: "SMB", 465: "SMTPS", 500: "ISAKMP",
    513: "rlogin", 514: "Syslog", 515: "LPD", 543: "Klogin",
    544: "Kshell", 548: "AFP", 554: "RTSP", 587: "Submission",
    631: "IPP", 636: "LDAPS", 646: "LDP", 808: "HTTP-Alt",
    873: "rsync", 990: "FTPS", 993: "IMAPS", 995: "POP3S",
    1000: "Webmin", 1024: "Reserved", 1025: "NFS-or-IIS",
    1080: "SOCKS", 1110: "EasyLink", 1433: "MSSQL", 1434: "MSSQL-Mon",
    1521: "Oracle", 1720: "H.323", 1723: "PPTP", 1755: "MMS",
    1801: "MSMQ", 1900: "SSDP/UPnP", 2000: "Cisco-SCCP",
    2001: "DCAP", 2049: "NFS", 2082: "cPanel", 2083: "cPanel-SSL",
    2121: "FTP-Alt", 2222: "SSH-Alt", 2381: "Compaq-HTTPS",
    2383: "SQL-Analysis", 2601: "Zebra", 2604: "Zebra-OSPF",
    2717: "PN-Requester", 2869: "SSDP-Event", 2967: "SSC-Agent",
    3000: "Grafana", 3001: "Nessus", 3128: "Squid-Proxy",
    3283: "Apple-Remote", 3306: "MySQL", 3389: "RDP", 3689: "DAAP",
    3703: "ADOBESERVER", 3986: "MAPPER", 4001: "Cisco-NBAR",
    4443: "HTTPS-Alt", 4444: "Metasploit", 4899: "Radmin",
    5000: "UPnP", 5001: "Synology", 5002: "RFE", 5009: "Airport",
    5050: "Yahoo-Msg", 5060: "SIP", 5101: "Yahoo-P2P",
    5120: "BNET", 5190: "AIM/ICQ", 5357: "WS-Discovery",
    5432: "PostgreSQL", 5601: "Kibana", 5631: "pcAnywhere",
    5666: "NRPE", 5800: "VNC-HTTP", 5900: "VNC", 5901: "VNC-1",
    6000: "X11", 6001: "X11-1", 6002: "X11-2", 6003: "X11-3",
    6004: "X11-4", 6379: "Redis", 6646: "McAfee",
    6667: "IRC", 7000: "AFS3", 7070: "RealServer", 7443: "Oracle-HTTPS",
    8000: "HTTP-Alt", 8008: "HTTP-Alt", 8009: "AJP13",
    8010: "XMPP", 8028: "HTTP-Alt", 8031: "HTTP-Alt",
    8080: "HTTP-Proxy", 8081: "HTTP-Proxy", 8082: "HTTP-Proxy",
    8083: "HTTP-Proxy", 8084: "HTTP-Proxy", 8085: "HTTP-Proxy",
    8086: "InfluxDB", 8087: "Riak", 8088: "Riak-HTTP",
    8089: "Splunk", 8200: "Vault", 8291: "Mikrotik",
    8443: "HTTPS-Alt", 8880: "CDDBP-Alt", 8888: "HTTP-Alt",
    9000: "SonarQube", 9001: "Tor-ORPort", 9090: "WebConsole",
    9100: "JetDirect", 9102: "Bacula", 9200: "Elasticsearch",
    9300: "ES-Transport", 9800: "WebDAV", 9801: "WebDAV-SSL",
    9999: "Urchin", 10000: "Webmin", 10010: "rxapi",
    11211: "Memcached", 18080: "HTTP-Alt", 27017: "MongoDB",
    32768: "RPC", 49152: "Dynamic", 49153: "Dynamic",
    49154: "Dynamic", 49155: "Dynamic", 49156: "Dynamic",
    49157: "Dynamic",
}

# ── CVE Database ───────────────────────────────────────────────
CVE_DATABASE = {
    "apache/2.4": [
        ("CVE-2021-41773", "Path traversal in Apache 2.4.49"),
        ("CVE-2024-38475", "Apache 2.4.x mod_rewrite RCE"),
        ("CVE-2023-25690", "HTTP request smuggling"),
    ],
    "apache": [
        ("CVE-2021-41773", "Path traversal in Apache 2.4.49"),
        ("CVE-2024-38475", "mod_rewrite vulnerability"),
    ],
    "nginx": [
        ("CVE-2024-32760", "nginx HTTP/3 QUIC vulnerability"),
        ("CVE-2023-44487", "HTTP/2 Rapid Reset (affects nginx)"),
        ("CVE-2022-41741", "nginx mp4 module memory corruption"),
    ],
    "openssh": [
        ("CVE-2024-6387", "regreSSHion - RCE in OpenSSH (glibc)"),
        ("CVE-2023-48795", "Terrapin attack - prefix truncation"),
        ("CVE-2023-51385", "OS command injection via ssh"),
    ],
    "ssh-2.0": [
        ("CVE-2024-6387", "regreSSHion - OpenSSH signal handler race"),
        ("CVE-2023-48795", "Terrapin attack"),
    ],
    "vsftpd": [
        ("CVE-2011-2523", "vsftpd 2.3.4 backdoor command execution"),
    ],
    "proftpd": [
        ("CVE-2023-51713", "ProFTPD FTPS out-of-bounds read"),
        ("CVE-2019-12815", "ProFTPD mod_copy arbitrary file copy"),
    ],
    "pure-ftpd": [
        ("CVE-2020-9365", "Pure-FTPd out-of-bounds read"),
    ],
    "microsoft-iis": [
        ("CVE-2022-21907", "HTTP Protocol Stack RCE"),
        ("CVE-2023-36899", "ASP.NET elevation of privilege"),
    ],
    "microsoft": [
        ("CVE-2024-43451", "NTLM hash disclosure spoofing"),
        ("CVE-2024-30051", "Windows DWM EoP"),
    ],
    "mysql": [
        ("CVE-2024-21008", "MySQL Server optimizer vulnerability"),
        ("CVE-2023-22078", "MySQL Server optimizer DoS"),
    ],
    "mariadb": [
        ("CVE-2023-22084", "MariaDB InnoDB vulnerability"),
    ],
    "postgresql": [
        ("CVE-2024-7348", "PostgreSQL pg_dump arbitrary SQL"),
        ("CVE-2023-5868", "PostgreSQL aggregate function memory leak"),
    ],
    "redis": [
        ("CVE-2024-31449", "Redis Lua library heap overflow"),
        ("CVE-2023-45145", "Redis Unix socket permission race"),
    ],
    "mongodb": [
        ("CVE-2024-1351", "MongoDB Server BSON DoS"),
    ],
    "elasticsearch": [
        ("CVE-2023-31419", "Elasticsearch StackOverflow DoS"),
    ],
    "exim": [
        ("CVE-2023-42115", "Exim AUTH out-of-bounds write"),
    ],
    "postfix": [
        ("CVE-2023-51764", "Postfix SMTP smuggling"),
    ],
    "dovecot": [
        ("CVE-2024-23184", "Dovecot large header DoS"),
    ],
    "samba": [
        ("CVE-2023-4091", "Samba SMB truncation read via acls"),
    ],
}

# ── Colors ─────────────────────────────────────────────────────
class C:
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

print_lock = threading.Lock()

def cprint(text, color=C.RESET):
    with print_lock:
        msg = f"{color}{text}{C.RESET}"
        try:
            if HAS_TQDM:
                tqdm.write(msg)
            else:
                print(msg, flush=True)
        except UnicodeEncodeError:
            safe = msg.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
            if HAS_TQDM:
                tqdm.write(safe)
            else:
                print(safe, flush=True)

# ── Banner Grabbing ────────────────────────────────────────────
def grab_banner(target, port, timeout=2, is_ipv6=False):
    """Protocol-aware banner grabbing for common services."""
    try:
        af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
        # HTTPS ports – use SSL
        if port in (443, 8443, 4443, 9443):
            return _grab_https_banner(target, port, timeout, is_ipv6)

        with socket.socket(af, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target, port))

            # HTTP
            if port in (80, 8080, 8000, 8008, 8081, 8082, 8888, 81, 82):
                s.sendall(f"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode())
            # FTP – read welcome, then send FEAT
            elif port in (21, 2121):
                banner = s.recv(1024).decode(errors="ignore").strip()
                s.sendall(b"QUIT\r\n")
                return banner[:300] if banner else ""
            # SSH – just read
            elif port == 22 or port == 2222:
                pass  # SSH sends banner automatically
            # SMTP
            elif port in (25, 465, 587):
                banner = s.recv(1024).decode(errors="ignore").strip()
                s.sendall(b"QUIT\r\n")
                return banner[:300] if banner else ""
            # POP3
            elif port in (110, 995):
                banner = s.recv(1024).decode(errors="ignore").strip()
                s.sendall(b"QUIT\r\n")
                return banner[:300] if banner else ""
            # IMAP
            elif port in (143, 993):
                banner = s.recv(1024).decode(errors="ignore").strip()
                s.sendall(b"a001 LOGOUT\r\n")
                return banner[:300] if banner else ""
            # MySQL
            elif port == 3306:
                pass  # MySQL sends greeting packet automatically
            # Redis
            elif port == 6379:
                s.sendall(b"PING\r\n")
            # MongoDB
            elif port == 27017:
                pass  # Will try to read any initial response
            # Telnet
            elif port == 23:
                pass
            # Memcached
            elif port == 11211:
                s.sendall(b"version\r\n")
            # Elasticsearch
            elif port in (9200, 9300):
                s.sendall(f"GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode())
            # Default: just try to read
            else:
                pass

            banner = s.recv(1024).decode(errors="ignore").strip()
            return banner[:300] if banner else ""
    except Exception:
        return ""


def _tcp_connect(target, port, timeout, is_ipv6=False):
    """Create a TCP connection using the correct address family. Returns a connected socket."""
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    s = socket.socket(af, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((target, port))
    except Exception:
        s.close()
        raise
    return s


def _grab_https_banner(target, port, timeout, is_ipv6=False):
    """Grab banner via TLS connection."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = _tcp_connect(target, port, timeout, is_ipv6)
        try:
            with ctx.wrap_socket(raw, server_hostname=target) as s:
                s.sendall(f"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode())
                banner = s.recv(1024).decode(errors="ignore").strip()
                return banner[:300] if banner else ""
        finally:
            try:
                raw.close()
            except Exception:
                pass
    except Exception as e:
        logger.debug("HTTPS banner grab failed for %s:%d: %s", target, port, e)
        return ""

# ── SSL/TLS Certificate Analysis ──────────────────────────────
def get_ssl_cert_info(target, port, timeout=3, is_ipv6=False):
    """Extract SSL certificate information."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_OPTIONAL
        raw = _tcp_connect(target, port, timeout, is_ipv6)
        try:
            with ctx.wrap_socket(raw, server_hostname=target) as s:
                cert = s.getpeercert()
                if not cert:
                    return None

                result = {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "version": cert.get("version"),
                    "serial": cert.get("serialNumber"),
                    "notBefore": cert.get("notBefore"),
                    "notAfter": cert.get("notAfter"),
                    "subjectAltName": [x[1] for x in cert.get("subjectAltName", [])],
                }

                # Parse dates — use timezone-aware comparison
                if result["notAfter"]:
                    try:
                        not_after = email.utils.parsedate_to_datetime(result["notAfter"])
                        now = datetime.now(not_after.tzinfo) if not_after.tzinfo else datetime.now()
                        days_left = (not_after - now).days
                        result["days_until_expiry"] = days_left
                        result["expired"] = days_left < 0
                        result["expiring_soon"] = 0 <= days_left < 30
                    except Exception as e:
                        logger.debug("SSL cert date parse error: %s", e)

                return result
        finally:
            try:
                raw.close()
            except Exception:
                pass
    except Exception as e:
        logger.debug("SSL cert info failed for %s:%d: %s", target, port, e)
        return None

# ── CVE Matching ───────────────────────────────────────────────
def match_cves(banner):
    """Match banner text against CVE database. Returns list of (cve_id, description)."""
    if not banner:
        return []
    banner_lower = banner.lower()
    matched = []
    seen = set()
    for keyword, cves in CVE_DATABASE.items():
        if keyword in banner_lower:
            for cve_id, desc in cves:
                if cve_id not in seen:
                    matched.append((cve_id, desc))
                    seen.add(cve_id)
    return matched

# ── Admin/Root Check ───────────────────────────────────────────
def is_admin():
    """Check if running with elevated privileges."""
    if platform.system() == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0

# ── CVE Database Update ────────────────────────────────────────
def _get_cve_cache_path():
    """Return the CVE cache file path in the script directory."""
    return os.path.join(_get_script_dir(), "cve_cache.json")


def load_cve_cache():
    """Load CVE cache from file if valid."""
    cache_file = _get_cve_cache_path()
    try:
        if os.path.exists(cache_file):
            with open(cache_file, "r") as f:
                cache = json.load(f)
                timestamp = cache.get("timestamp")
                if timestamp:
                    cache_time = datetime.fromisoformat(timestamp)
                    if datetime.now() - cache_time < timedelta(hours=24):
                        return cache.get("cves", {})
    except Exception:
        pass
    return None


def save_cve_cache(cves):
    """Save CVE cache to file."""
    cache_file = _get_cve_cache_path()
    try:
        cache = {"timestamp": datetime.now().isoformat(), "cves": cves}
        with open(cache_file, "w") as f:
            json.dump(cache, f)
    except Exception:
        pass


def update_cve_database(api_key=None, lang_code="en"):
    """Fetch CVEs from NVD REST API and merge with hardcoded database."""
    L = LANG[lang_code]
    cprint(L["updating_cve"], C.CYAN)

    # Check cache first
    cached = load_cve_cache()
    if cached:
        return cached

    merged_cves = dict(CVE_DATABASE)

    keywords = [
        "apache", "nginx", "openssh", "mysql", "postgresql", "redis",
        "mongodb", "elasticsearch", "vsftpd", "samba", "postfix"
    ]

    for keyword in keywords:
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=5"
            if api_key:
                url += f"&apiKey={api_key}"

            req = urllib.request.Request(url, headers={"User-Agent": "Canavar-Scanner/2026"})
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode())

                if "vulnerabilities" in data:
                    for vuln in data["vulnerabilities"][:5]:
                        cve_id = vuln.get("cve", {}).get("id", "")
                        desc = vuln.get("cve", {}).get("descriptions", [{}])[0].get("value", "")
                        if cve_id:
                            if keyword not in merged_cves:
                                merged_cves[keyword] = []
                            merged_cves[keyword].append((cve_id, desc[:100]))

            time.sleep(0.5)  # Rate limiting
        except Exception:
            continue

    save_cve_cache(merged_cves)
    cprint(L["cve_updated"], C.GREEN)
    return merged_cves

# ── Target Resolution ─────────────────────────────────────────
def resolve_targets(target_str):
    """Resolve target string to list of (display_name, ip, is_ipv6) tuples.
    Supports: single IP, hostname, IPv6, CIDR notation."""
    targets = []
    try:
        # Try CIDR
        if "/" in target_str:
            network = ipaddress.ip_network(target_str, strict=False)
            # Safety limit for IPv6 CIDR — prevent iterating quintillions of hosts
            max_hosts = 65536
            if isinstance(network, ipaddress.IPv6Network) and network.num_addresses > max_hosts:
                cprint(f"[!] IPv6 CIDR too large ({network.num_addresses} hosts). Limiting to first {max_hosts}.", C.YELLOW)
            host_count = 0
            for host in network.hosts():
                ip = str(host)
                is_ipv6 = isinstance(host, ipaddress.IPv6Address)
                targets.append((ip, ip, is_ipv6))
                host_count += 1
                if host_count >= max_hosts:
                    break
            if not targets:  # /32 or /128 network
                ip = str(network.network_address)
                is_ipv6 = isinstance(network.network_address, ipaddress.IPv6Address)
                targets.append((ip, ip, is_ipv6))
            return targets
        # Try as IP
        addr = ipaddress.ip_address(target_str)
        is_ipv6 = isinstance(addr, ipaddress.IPv6Address)
        return [(target_str, target_str, is_ipv6)]
    except ValueError:
        pass
    # Treat as hostname
    try:
        ip = socket.gethostbyname(target_str)
        return [(target_str, ip, False)]
    except socket.gaierror as e:
        raise ValueError(f"Cannot resolve '{target_str}': {e}")

# ── Port Parsing ──────────────────────────────────────────────
def parse_ports(port_str, top_ports=None):
    """Parse port specification string. Supports: 80 | 1-1024 | 22,80,443 | 22,80,8000-9000"""
    if top_ports:
        n = min(top_ports, len(TOP_PORTS))
        return sorted(TOP_PORTS[:n])
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            s, e = int(start), int(end)
            if s > e or s < 1 or e > 65535:
                raise ValueError(f"Invalid port range: {part}")
            ports.update(range(s, e + 1))
        else:
            p = int(part)
            if p < 1 or p > 65535:
                raise ValueError(f"Invalid port: {p}")
            ports.add(p)
    return sorted(ports)

# ── Host Discovery ────────────────────────────────────────────
def ping_host_tcp(target, timeout=2, is_ipv6=False):
    """Try TCP connect to common HTTP ports to check if host is alive."""
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    for port in [80, 443, 22, 21]:
        try:
            with socket.socket(af, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((target, port)) == 0:
                    return True
        except Exception:
            pass
    return False


def ping_host_icmp(target, timeout=1):
    """Try ICMP ping via system command."""
    try:
        if platform.system() == "Windows":
            cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), target]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), target]
        result = subprocess.run(cmd, capture_output=True, timeout=timeout + 1)
        return result.returncode == 0
    except Exception:
        return False


def discover_hosts(targets, timeout=3):
    """Filter targets by checking which hosts are alive."""
    alive = []
    for display_name, ip, is_ipv6 in targets:
        if ping_host_tcp(ip, timeout, is_ipv6) or ping_host_icmp(ip, timeout):
            alive.append((display_name, ip, is_ipv6))
    return alive

# ── OS Fingerprinting (TTL-based) ────────────────────────────
def os_fingerprint(target, port=80, timeout=2, is_ipv6=False):
    """Guess OS based on TTL analysis.
    Uses ICMP ping TTL when available, falls back to banner-based heuristics.
    Note: Pure socket getsockopt reads local TTL, not the remote host's."""
    # Method 1: Parse TTL from ping output
    ttl = _get_ping_ttl(target, timeout)
    if ttl is not None:
        if ttl <= 64:
            return f"Linux/macOS (TTL: {ttl})"
        elif ttl <= 128:
            return f"Windows (TTL: {ttl})"
        elif ttl <= 255:
            return f"Solaris/Network Device (TTL: {ttl})"
        else:
            return f"Unknown (TTL: {ttl})"

    # Method 2: Try connecting and reading banner for OS hints
    try:
        af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
        with socket.socket(af, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target, port))
            banner = s.recv(1024).decode(errors="ignore").lower()
            if "ubuntu" in banner or "debian" in banner:
                return "Linux (Ubuntu/Debian)"
            elif "centos" in banner or "red hat" in banner:
                return "Linux (CentOS/RHEL)"
            elif "microsoft" in banner or "windows" in banner:
                return "Windows"
            elif "freebsd" in banner:
                return "FreeBSD"
    except Exception:
        pass
    return None


def _get_ping_ttl(target, timeout=2):
    """Extract TTL value from ping output."""
    try:
        if platform.system() == "Windows":
            cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), target]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
        if result.returncode == 0:
            # Parse TTL from output (e.g., "TTL=64" or "ttl=64")
            match = re.search(r'ttl[=:]\s*(\d+)', result.stdout, re.IGNORECASE)
            if match:
                return int(match.group(1))
    except Exception:
        pass
    return None

# ── Port Scanning ─────────────────────────────────────────────

def tcp_scan_port(target, port, results, results_lock, lang_code, no_banner=False, dashboard_state=None,
                  timeout=1.5, is_ipv6=False, retries=0, stop_event=None):
    """TCP Connect scan for a single port with latency recording."""
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET

    for attempt in range(retries + 1):
        if stop_event and stop_event.is_set():
            return
        try:
            start_time = time.time()
            with socket.socket(af, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((target, port)) == 0:
                    latency_ms = (time.time() - start_time) * 1000
                    banner = "" if no_banner else grab_banner(target, port, timeout, is_ipv6)
                    service = WELL_KNOWN_PORTS.get(port, "Unknown")
                    cves = match_cves(banner)

                    # Get SSL cert info for HTTPS ports
                    cert_info = None
                    if port in (443, 8443, 4443, 9443):
                        cert_info = get_ssl_cert_info(target, port, timeout, is_ipv6)

                    entry = {
                        "port": port, "state": "open", "service": service,
                        "banner": banner, "scan_type": "TCP",
                        "cves": [c[0] for c in cves], "cve_details": cves,
                        "latency_ms": round(latency_ms, 2),
                        "cert_info": cert_info,
                    }
                    with results_lock:
                        results.append(entry)
                    if dashboard_state:
                        dashboard_state.add_event("port_found", {**entry, "target": target})
                    L = LANG[lang_code]
                    line = L["port_open"].format(
                        port=port, stype="TCP", service=service,
                        banner=banner[:60] if banner else L["no_banner"]
                    )
                    line += f" | {latency_ms:.1f}ms"
                    if cves:
                        line += C.RED + L["cve_hint"].format(cves=", ".join(c[0] for c in cves))
                    cprint(line, C.GREEN)
                    return
        except Exception as e:
            logger.debug("TCP scan error %s:%d attempt %d: %s", target, port, attempt, e)
            if attempt < retries:
                time.sleep(0.2)
                continue
            else:
                pass


def udp_scan_port(target, port, results, results_lock, lang_code, no_banner=False, dashboard_state=None,
                  timeout=1.5, is_ipv6=False, retries=0, stop_event=None):
    """UDP scan for a single port. Send protocol-specific probes for known services."""
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET

    for attempt in range(retries + 1):
        if stop_event and stop_event.is_set():
            return
        try:
            start_time = time.time()
            with socket.socket(af, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)

                # Send protocol-specific probes
                probe = b""
                if port == 53:  # DNS
                    probe = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                elif port == 161:  # SNMP
                    probe = b"\x30\x00"
                elif port in (67, 68):  # DHCP
                    probe = b"\x01\x01\x06\x00" + b"\x00" * 240
                elif port == 123:  # NTP
                    probe = b"\x1b" + b"\x00" * 47
                elif port == 69:  # TFTP
                    probe = b"\x00\x01test\x00octet\x00"

                if probe:
                    s.sendto(probe, (target, port))
                else:
                    s.sendto(b"", (target, port))

                try:
                    data, _ = s.recvfrom(1024)
                    latency_ms = (time.time() - start_time) * 1000
                    service = WELL_KNOWN_PORTS.get(port, "Unknown")
                    entry = {
                        "port": port, "state": "open", "service": service,
                        "banner": "", "scan_type": "UDP",
                        "cves": [], "cve_details": [],
                        "latency_ms": round(latency_ms, 2),
                    }
                    with results_lock:
                        results.append(entry)
                    if dashboard_state:
                        dashboard_state.add_event("port_found", {**entry, "target": target})
                    L = LANG[lang_code]
                    line = L["port_open"].format(
                        port=port, stype="UDP", service=service,
                        banner=L["no_banner"]
                    )
                    line += f" | {latency_ms:.1f}ms"
                    cprint(line, C.GREEN)
                    return
                except socket.timeout:
                    pass
        except Exception as e:
            logger.debug("UDP scan error %s:%d attempt %d: %s", target, port, attempt, e)
            if attempt < retries:
                time.sleep(0.2)
                continue
            else:
                pass


def syn_scan_port(target, port, results, results_lock, lang_code, no_banner=False, dashboard_state=None,
                  timeout=1.5, is_ipv6=False, retries=0, stop_event=None):
    """SYN (half-open) scan for a single port. Requires scapy + root."""
    for attempt in range(retries + 1):
        if stop_event and stop_event.is_set():
            return
        try:
            start_time = time.time()
            pkt = IP(dst=target) / TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=timeout, verbose=0)
            if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
                latency_ms = (time.time() - start_time) * 1000
                # Use our original source port (which equals resp[TCP].dport, since the
                # target's reply swaps source/destination) so the RST matches the SYN's 4-tuple.
                rst = IP(dst=target) / TCP(dport=port, sport=resp[TCP].dport,
                                            flags="R", seq=resp[TCP].ack)
                send(rst, verbose=0)
                banner = "" if no_banner else grab_banner(target, port, timeout, is_ipv6)
                service = WELL_KNOWN_PORTS.get(port, "Unknown")
                cves = match_cves(banner)
                entry = {
                    "port": port, "state": "open", "service": service,
                    "banner": banner, "scan_type": "SYN",
                    "cves": [c[0] for c in cves], "cve_details": cves,
                    "latency_ms": round(latency_ms, 2),
                }
                with results_lock:
                    results.append(entry)
                if dashboard_state:
                    dashboard_state.add_event("port_found", {**entry, "target": target})
                L = LANG[lang_code]
                line = L["port_open"].format(
                    port=port, stype="SYN", service=service,
                    banner=banner[:60] if banner else L["no_banner"]
                )
                line += f" | {latency_ms:.1f}ms"
                if cves:
                    line += C.RED + L["cve_hint"].format(cves=", ".join(c[0] for c in cves))
                cprint(line, C.GREEN)
                return
        except Exception as e:
            logger.debug("SYN scan error %s:%d attempt %d: %s", target, port, attempt, e)
            if attempt < retries:
                time.sleep(0.2)
                continue
            else:
                pass

# ── Scan Orchestrator ─────────────────────────────────────────
def run_scan(target_ip, target_name, ports, threads, use_syn, lang_code,
             no_banner=False, dashboard_state=None, timeout=1.5, udp_ports=None,
             is_ipv6=False, retries=0, delay=0.0):
    """Run a port scan against a single target. Returns results list."""
    L = LANG[lang_code]
    results = []
    results_lock = threading.Lock()
    stop_event = threading.Event()
    queue = Queue()

    # Add TCP/SYN ports to queue
    for port in ports:
        queue.put(("tcp", port))

    # Add UDP ports if specified
    if udp_ports:
        for port in udp_ports:
            queue.put(("udp", port))

    total = len(ports) + (len(udp_ports) if udp_ports else 0)

    scan_fn = syn_scan_port if use_syn else tcp_scan_port
    scanned_count = [0]
    count_lock = threading.Lock()

    pbar = None
    if HAS_TQDM:
        pbar = tqdm(total=total, desc=f"  {L['progress']} {target_name}",
                    unit="port", ncols=90, bar_format=
                    "{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
                    colour="cyan")

    def worker():
        while not queue.empty() and not stop_event.is_set():
            try:
                scan_type, port = queue.get_nowait()
            except Exception:
                break

            if scan_type == "tcp":
                scan_fn(target_ip, port, results, results_lock, lang_code, no_banner, dashboard_state,
                        timeout, is_ipv6, retries, stop_event)
            else:  # UDP
                udp_scan_port(target_ip, port, results, results_lock, lang_code, no_banner, dashboard_state,
                              timeout, is_ipv6, retries, stop_event)

            # Apply timing delay if configured (for stealth profiles)
            if delay > 0:
                time.sleep(delay)

            with count_lock:
                scanned_count[0] += 1
                if dashboard_state and scanned_count[0] % 10 == 0:
                    dashboard_state.add_event("progress", {
                        "scanned": scanned_count[0], "total": total,
                        "target": target_name
                    })
            if pbar:
                pbar.update(1)
            queue.task_done()

    thread_list = []
    for _ in range(min(threads, total if total > 0 else 1)):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        thread_list.append(t)

    queue.join()
    if pbar:
        pbar.close()
    if dashboard_state:
        dashboard_state.add_event("progress", {"scanned": total, "total": total, "target": target_name})

    results.sort(key=lambda x: x["port"])
    return results

# ── Export Functions ───────────────────────────────────────────
def _normalize_for_json(data):
    """Convert non-JSON-native types (tuples, datetime) into serializable forms.
    Specifically converts cve_details tuple lists into list-of-lists so round-tripping
    through JSON is consistent."""
    for td in data.get("targets", []):
        for r in td.get("results", []):
            cd = r.get("cve_details")
            if cd:
                r["cve_details"] = [list(item) if isinstance(item, tuple) else item for item in cd]
    return data


def export_json(scan_data, filename):
    _normalize_for_json(scan_data)
    with open(f"{filename}.json", "w", encoding="utf-8") as f:
        json.dump(scan_data, f, indent=2, ensure_ascii=False)


def export_csv(scan_data, filename):
    with open(f"{filename}.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Target", "Port", "State", "Service", "Banner",
                         "Scan Type", "CVE Suggestions", "Latency (ms)", "OS", "Cert Info"])
        for target_data in scan_data.get("targets", []):
            tgt = target_data["target"]
            os_detect = target_data.get("os_detection", "")
            for r in target_data["results"]:
                cert_str = ""
                if r.get("cert_info"):
                    cert = r["cert_info"]
                    cn = cert.get("subject", {}).get("commonName", "")
                    cert_str = f"CN={cn}"
                writer.writerow([
                    tgt, r["port"], r["state"], r["service"],
                    r["banner"], r["scan_type"], "; ".join(r["cves"]),
                    r.get("latency_ms", ""), os_detect, cert_str
                ])


def export_html(scan_data, filename, lang_code="en"):
    html = generate_html_report(scan_data, lang_code)
    filepath = f"{filename}.html"
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)
    return filepath

# ── HTML Report Generation ────────────────────────────────────
def generate_html_report(scan_data, lang_code="en"):
    L = LANG[lang_code]
    meta = scan_data["metadata"]

    # Load logo as base64
    logo_b64 = get_logo_base64(180)
    if logo_b64:
        logo_html = f'<img src="data:image/png;base64,{logo_b64}" alt="Canavar Logo" class="header-logo" />'
    else:
        logo_html = ''

    # Collect all results across targets
    all_results = []
    for td in scan_data.get("targets", []):
        for r in td["results"]:
            r["_target"] = td["target"]
            r["_os"] = td.get("os_detection", "")
            all_results.append(r)

    all_cves = {}
    for r in all_results:
        for cve_id, desc in r.get("cve_details", []):
            if cve_id not in all_cves:
                all_cves[cve_id] = {"desc": desc, "ports": []}
            all_cves[cve_id]["ports"].append(f"{r['_target']}:{r['port']}")

    total_open = len(all_results)
    avg_latency = sum(r.get("latency_ms", 0) for r in all_results) / len(all_results) if all_results else 0

    # Build table rows
    rows_html = ""
    for r in all_results:
        cve_badges = ""
        if r["cves"]:
            cve_badges = " ".join(
                f'<a href="https://nvd.nist.gov/vuln/detail/{html_escape(c)}" '
                f'target="_blank" class="badge badge-cve">{html_escape(c)}</a>'
                for c in r["cves"]
            )
        else:
            cve_badges = '<span class="text-muted">—</span>'

        scan_cls = "badge-syn" if r["scan_type"] == "SYN" else ("badge-udp" if r["scan_type"] == "UDP" else "badge-tcp")
        banner_safe = html_escape(r["banner"][:100]) if r["banner"] else L["no_banner"]
        banner_full = html_escape(r["banner"]) if r["banner"] else ""

        cert_info_html = ""
        if r.get("cert_info"):
            cert = r["cert_info"]
            cn = cert.get("subject", {}).get("commonName", "?")
            status = "🔴" if cert.get("expired") else ("🟡" if cert.get("expiring_soon") else "🟢")
            cert_info_html = f'<span class="badge badge-cert">{status} {cn}</span>'

        rows_html += f"""<tr>
<td><span class="port-num">{r['port']}</span></td>
<td><span class="badge badge-service">{html_escape(r['service'])}</span></td>
<td><span class="badge badge-open">● OPEN</span></td>
<td class="banner-cell" title="{banner_full}">{banner_safe}</td>
<td><span class="badge {scan_cls}">{r['scan_type']}</span></td>
<td>{r.get('latency_ms', '?')}ms</td>
<td>{cert_info_html}</td>
<td><div class="cve-list">{cve_badges}</div></td>
</tr>\n"""

    # Build CVE section
    cve_cards = ""
    for cve_id, info in all_cves.items():
        ports_str = ", ".join(info["ports"][:5])
        cve_cards += f"""<div class="cve-card">
<div class="cve-icon">⚠</div>
<div class="cve-info">
<h3><a href="https://nvd.nist.gov/vuln/detail/{html_escape(cve_id)}" target="_blank"
class="cve-link">{html_escape(cve_id)}</a></h3>
<p>{html_escape(info['desc'])}</p>
<p class="text-muted">Ports: {html_escape(ports_str)}</p>
</div></div>\n"""

    cve_section = ""
    if all_cves:
        cve_section = f"""<div class="section cve-section">
<div class="section-header"><h2>⚠ {L['cve']}</h2>
<span class="count">{len(all_cves)}</span></div>
{cve_cards}</div>"""

    table_content = f"""<div class="filter-bar">
<input type="text" id="filter" placeholder="🔍 Filter..." /></div>
<table><thead><tr>
<th>{L['port']}</th><th>{L['service']}</th><th>{L['status']}</th>
<th>{L['banner']}</th><th>{L['scan_type']}</th><th>{L['latency']}</th><th>{L['ssl_cert']}</th><th>{L['cve']}</th>
</tr></thead><tbody>{rows_html}</tbody></table>""" if total_open > 0 else f"""<div class="no-results"><div class="icon">🔒</div><p>{L['no_open']}</p></div>"""

    target_display = meta.get("targets_display", meta.get("target", ""))
    duration_str = f"{meta.get('duration_seconds', 0):.2f}s"
    timing_info = meta.get("timing_profile", "")
    timing_display = f" • {timing_info}" if timing_info else ""

    return f"""<!DOCTYPE html>
<html lang="{lang_code}"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Canavar - {L['report_title']}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{{--bg:#0f0f1a;--bg2:#1a1a2e;--card:rgba(255,255,255,0.03);--card-h:rgba(255,255,255,0.06);
--brd:rgba(255,255,255,0.08);--t1:#e2e8f0;--t2:#94a3b8;--tm:#64748b;
--cyan:#06b6d4;--purple:#8b5cf6;--green:#10b981;--amber:#f59e0b;--red:#ef4444;--blue:#3b82f6;
--grad:linear-gradient(135deg,#06b6d4,#8b5cf6);}}
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--t1);line-height:1.6;min-height:100vh;}}
body::before{{content:'';position:fixed;inset:0;
background:radial-gradient(ellipse at 20% 50%,rgba(6,182,212,.08) 0%,transparent 50%),
radial-gradient(ellipse at 80% 20%,rgba(139,92,246,.08) 0%,transparent 50%),
radial-gradient(ellipse at 50% 80%,rgba(16,185,129,.05) 0%,transparent 50%);pointer-events:none;z-index:0;}}
.wrap{{max-width:1260px;margin:0 auto;padding:2rem;position:relative;z-index:1;}}
.header{{text-align:center;padding:2.5rem 2rem;margin-bottom:2rem;
background:linear-gradient(135deg,rgba(6,182,212,.1),rgba(139,92,246,.1));
border:1px solid var(--brd);border-radius:20px;backdrop-filter:blur(10px);animation:fadeDown .6s ease-out;}}
.header-logo{{width:120px;height:120px;margin:0 auto 1rem;display:block;
filter:drop-shadow(0 0 20px rgba(6,182,212,.4)) drop-shadow(0 0 40px rgba(139,92,246,.2));
animation:logoPulse 3s ease-in-out infinite alternate;}}
@keyframes logoPulse{{from{{filter:drop-shadow(0 0 20px rgba(6,182,212,.4)) drop-shadow(0 0 40px rgba(139,92,246,.2));}}
to{{filter:drop-shadow(0 0 30px rgba(6,182,212,.6)) drop-shadow(0 0 50px rgba(139,92,246,.4));}}}}
.header h1{{font-size:2.5rem;font-weight:800;background:var(--grad);
-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;
letter-spacing:-.02em;margin-bottom:.3rem;}}
.header .sub{{color:var(--t2);font-size:1rem;}}
.header .meta{{margin-top:1rem;display:flex;justify-content:center;gap:2rem;flex-wrap:wrap;}}
.header .mi{{display:flex;align-items:center;gap:.4rem;color:var(--t2);font-size:.85rem;}}
.header .mi strong{{color:var(--t1);}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1.2rem;margin-bottom:2rem;animation:fadeUp .6s ease-out .15s both;}}
.sc{{background:var(--card);border:1px solid var(--brd);border-radius:16px;padding:1.4rem;
backdrop-filter:blur(10px);transition:all .3s;position:relative;overflow:hidden;}}
.sc::before{{content:'';position:absolute;top:0;left:0;right:0;height:3px;border-radius:16px 16px 0 0;}}
.sc:nth-child(1)::before{{background:var(--cyan);}} .sc:nth-child(2)::before{{background:var(--green);}}
.sc:nth-child(3)::before{{background:var(--purple);}} .sc:nth-child(4)::before{{background:var(--amber);}}
.sc:hover{{background:var(--card-h);transform:translateY(-2px);border-color:rgba(255,255,255,.12);}}
.sc .sl{{font-size:.78rem;color:var(--tm);text-transform:uppercase;letter-spacing:.05em;font-weight:600;margin-bottom:.4rem;}}
.sc .sv{{font-size:2rem;font-weight:700;font-family:'JetBrains Mono',monospace;}}
.sc:nth-child(1) .sv{{color:var(--cyan);}} .sc:nth-child(2) .sv{{color:var(--green);}}
.sc:nth-child(3) .sv{{color:var(--purple);}} .sc:nth-child(4) .sv{{color:var(--amber);}}
.section{{background:var(--card);border:1px solid var(--brd);border-radius:16px;overflow:hidden;
margin-bottom:2rem;backdrop-filter:blur(10px);animation:fadeUp .6s ease-out .3s both;}}
.section-header{{padding:1.2rem 1.5rem;border-bottom:1px solid var(--brd);display:flex;align-items:center;gap:.7rem;}}
.section-header h2{{font-size:1.1rem;font-weight:600;}}
.count{{background:rgba(6,182,212,.15);color:var(--cyan);padding:.2rem .7rem;border-radius:100px;
font-size:.78rem;font-weight:600;font-family:'JetBrains Mono',monospace;}}
.filter-bar{{padding:.75rem 1.5rem;border-bottom:1px solid var(--brd);}}
.filter-bar input{{width:100%;padding:.5rem .8rem;background:rgba(255,255,255,.05);border:1px solid var(--brd);
border-radius:8px;color:var(--t1);font-size:.85rem;outline:none;transition:border-color .2s;}}
.filter-bar input:focus{{border-color:var(--cyan);}}
table{{width:100%;border-collapse:collapse;}}
thead th{{padding:.8rem 1.2rem;text-align:left;font-size:.72rem;font-weight:600;text-transform:uppercase;
letter-spacing:.05em;color:var(--tm);background:rgba(0,0,0,.2);border-bottom:1px solid var(--brd);cursor:pointer;
user-select:none;transition:color .2s;}}
thead th:hover{{color:var(--cyan);}}
tbody tr{{border-bottom:1px solid rgba(255,255,255,.03);transition:background .2s;}}
tbody tr:hover{{background:rgba(255,255,255,.03);}}
tbody td{{padding:.8rem 1.2rem;font-size:.85rem;}}
.port-num{{font-family:'JetBrains Mono',monospace;font-weight:600;color:var(--cyan);}}
.badge{{display:inline-flex;align-items:center;padding:.18rem .55rem;border-radius:100px;
font-size:.7rem;font-weight:600;text-transform:uppercase;letter-spacing:.03em;white-space:nowrap;}}
.badge-open{{background:rgba(16,185,129,.15);color:var(--green);}}
.badge-service{{background:rgba(139,92,246,.15);color:var(--purple);}}
.badge-tcp{{background:rgba(59,130,246,.15);color:var(--blue);}}
.badge-syn{{background:rgba(249,115,22,.15);color:#f97316;}}
.badge-udp{{background:rgba(168,85,247,.15);color:#a855f7;}}
.badge-cert{{background:rgba(100,200,100,.15);color:#64c864;}}
.badge-cve{{background:rgba(239,68,68,.15);color:var(--red);text-decoration:none;transition:background .2s;margin:.1rem;}}
.badge-cve:hover{{background:rgba(239,68,68,.25);}}
.banner-cell{{font-family:'JetBrains Mono',monospace;font-size:.78rem;color:var(--t2);max-width:320px;
overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}}
.cve-list{{display:flex;gap:.3rem;flex-wrap:wrap;}}
.text-muted{{color:var(--tm);font-size:.8rem;}}
.cve-section{{animation:fadeUp .6s ease-out .5s both;}}
.cve-card{{display:flex;align-items:flex-start;gap:1rem;padding:1rem 1.5rem;border-bottom:1px solid rgba(255,255,255,.03);}}
.cve-card:last-child{{border-bottom:none;}}
.cve-icon{{width:36px;height:36px;border-radius:10px;background:rgba(239,68,68,.15);
display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:1.1rem;}}
.cve-info h3{{font-size:.88rem;font-weight:600;margin-bottom:.2rem;}}
.cve-info p{{font-size:.8rem;color:var(--t2);}}
.cve-link{{color:var(--red);text-decoration:none;transition:color .2s;}}
.cve-link:hover{{color:#fca5a5;text-decoration:underline;}}
.no-results{{text-align:center;padding:3rem;color:var(--tm);}}
.no-results .icon{{font-size:3rem;margin-bottom:1rem;}}
.footer{{text-align:center;padding:2rem;color:var(--tm);font-size:.78rem;animation:fadeUp .6s ease-out .7s both;}}
@keyframes fadeDown{{from{{opacity:0;transform:translateY(-20px)}}to{{opacity:1;transform:translateY(0)}}}}
@keyframes fadeUp{{from{{opacity:0;transform:translateY(20px)}}to{{opacity:1;transform:translateY(0)}}}}
@media(max-width:768px){{.wrap{{padding:1rem;}}.header h1{{font-size:1.75rem;}}
.stats{{grid-template-columns:repeat(2,1fr);}}.header .meta{{flex-direction:column;align-items:center;gap:.5rem;}}
thead th,tbody td{{padding:.6rem .8rem;}}.banner-cell{{max-width:140px;}}}}
@media(max-width:480px){{.stats{{grid-template-columns:1fr;}}}}
@media print{{body{{background:#fff;color:#1a1a1a;}}body::before{{display:none;}}
.sc,.section,.header{{border-color:#ddd;backdrop-filter:none;background:#f8f8f8;}}
.port-num{{color:#0891b2;}}.badge-open{{color:#059669;background:#d1fae5;}}.badge-cve{{color:#dc2626;background:#fee2e2;}}}}
</style></head><body>
<div class="wrap">
<div class="header">
{logo_html}
<h1>CANAVAR</h1>
<p class="sub">{L['report_title']}</p>
<div class="meta">
<div class="mi"><span>{L['target']}:</span><strong>{html_escape(target_display)}</strong></div>
<div class="mi"><span>{L['scan_type']}:</span><strong>{html_escape(meta.get('scan_type','TCP'))}{html_escape(timing_display)}</strong></div>
<div class="mi"><span>{L['generated']}:</span><strong>{html_escape(str(meta.get('end_time','')))}</strong></div>
</div></div>
<div class="stats">
<div class="sc"><div class="sl">{L['ports_scanned']}</div><div class="sv">{meta.get('total_ports',0)}</div></div>
<div class="sc"><div class="sl">{L['open_ports']}</div><div class="sv">{total_open}</div></div>
<div class="sc"><div class="sl">{L['duration']}</div><div class="sv">{duration_str}</div></div>
<div class="sc"><div class="sl">{L['avg_latency']}</div><div class="sv">{avg_latency:.1f}ms</div></div>
</div>
<div class="section">
<div class="section-header"><h2>📡 {L['open_ports']}</h2><span class="count">{total_open}</span></div>
{table_content}
</div>
{cve_section}
<div class="footer">Canavar Port Scanner v2026 &bull; {L['generated']}: {html_escape(str(meta.get('end_time','')))}</div>
</div>
<script>
document.querySelectorAll('thead th').forEach((th,i)=>{{th.addEventListener('click',()=>{{
const tb=th.closest('table').querySelector('tbody');
const rows=Array.from(tb.querySelectorAll('tr'));
const d=th.dataset.d==='a'?'d':'a';th.dataset.d=d;
rows.sort((a,b)=>{{const av=a.cells[i].textContent.trim(),bv=b.cells[i].textContent.trim();
const an=parseInt(av),bn=parseInt(bv);
if(!isNaN(an)&&!isNaN(bn))return d==='a'?an-bn:bn-an;
return d==='a'?av.localeCompare(bv):bv.localeCompare(av);}});
rows.forEach(r=>tb.appendChild(r));}});}});
const fi=document.getElementById('filter');
if(fi){{fi.addEventListener('input',e=>{{const v=e.target.value.toLowerCase();
document.querySelectorAll('tbody tr').forEach(r=>{{r.style.display=r.textContent.toLowerCase().includes(v)?'':'none';}});}});}}
</script></body></html>"""

# ── Live Dashboard ─────────────────────────────────────────────
class DashboardState:
    """Shared state between scanner threads and dashboard server."""
    def __init__(self):
        self.events = []
        self.lock = threading.Lock()
        self.is_running = True
        self.metadata = {}

    def add_event(self, event_type, data):
        with self.lock:
            self.events.append({"type": event_type, "data": data,
                                "ts": datetime.now().isoformat()})

    def get_events_since(self, index):
        with self.lock:
            return list(self.events[index:]), len(self.events)


class _DashboardHandler(BaseHTTPRequestHandler):
    """HTTP handler for live dashboard with SSE support."""

    def log_message(self, *a):
        pass  # Suppress HTTP logs

    def do_GET(self):
        if self.path == "/":
            self._serve_html()
        elif self.path == "/events":
            self._serve_sse()
        elif self.path == "/api/state":
            self._serve_state()
        else:
            self.send_error(404)

    def _serve_html(self):
        html = _build_dashboard_html(self.server.dashboard_state)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def _serve_sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        last_idx = 0
        while self.server.dashboard_state.is_running:
            events, new_idx = self.server.dashboard_state.get_events_since(last_idx)
            for evt in events:
                try:
                    self.wfile.write(f"data: {json.dumps(evt)}\n\n".encode())
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    return
            last_idx = new_idx
            time.sleep(0.3)
        # Send final complete event
        try:
            self.wfile.write(f"data: {json.dumps({'type': 'scan_complete', 'data': {}})}\n\n".encode())
            self.wfile.flush()
        except Exception:
            pass

    def _serve_state(self):
        state = self.server.dashboard_state
        with state.lock:
            data = json.dumps({"events": list(state.events), "running": state.is_running})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data.encode())


class _ThreadedServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


def start_dashboard(port, state):
    """Start dashboard HTTP server in background thread."""
    server = _ThreadedServer(("127.0.0.1", port), _DashboardHandler)
    server.dashboard_state = state
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    url = f"http://localhost:{port}"
    cprint(f"[*] Dashboard: {url}", C.CYAN + C.BOLD)
    try:
        webbrowser.open(url)
    except Exception:
        pass
    return server


def _build_dashboard_html(state):
    logo_b64 = get_logo_base64(120)
    logo_img = f'<img src="data:image/png;base64,{logo_b64}" style="width:80px;height:80px;filter:drop-shadow(0 0 15px rgba(6,182,212,.5));margin-bottom:.5rem;" />' if logo_b64 else ''
    return f'''<!DOCTYPE html><html><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Canavar - Live Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{{--bg:#0f0f1a;--card:rgba(255,255,255,0.03);--brd:rgba(255,255,255,0.08);--t1:#e2e8f0;--t2:#94a3b8;--tm:#64748b;
--cyan:#06b6d4;--purple:#8b5cf6;--green:#10b981;--amber:#f59e0b;--red:#ef4444;--blue:#3b82f6;}}
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--t1);min-height:100vh;}}
body::before{{content:'';position:fixed;inset:0;background:radial-gradient(ellipse at 20% 50%,rgba(6,182,212,.08) 0%,transparent 50%),
radial-gradient(ellipse at 80% 20%,rgba(139,92,246,.08) 0%,transparent 50%);pointer-events:none;}}
.w{{max-width:1260px;margin:0 auto;padding:1.5rem;position:relative;z-index:1;}}
.hd{{text-align:center;padding:1.5rem;margin-bottom:1.5rem;background:linear-gradient(135deg,rgba(6,182,212,.1),rgba(139,92,246,.1));
border:1px solid var(--brd);border-radius:16px;backdrop-filter:blur(10px);}}
.hd h1{{font-size:2rem;font-weight:800;background:linear-gradient(135deg,#06b6d4,#8b5cf6);-webkit-background-clip:text;-webkit-text-fill-color:transparent;}}
.status{{display:inline-block;padding:.3rem 1rem;border-radius:100px;font-size:.8rem;font-weight:600;margin-top:.5rem;
background:rgba(6,182,212,.15);color:var(--cyan);animation:pulse 2s infinite;}}
.status.done{{background:rgba(16,185,129,.15);color:var(--green);animation:none;}}
@keyframes pulse{{0%,100%{{opacity:1;}}50%{{opacity:.5;}}}}
.sg{{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:1.5rem;}}
.sc{{background:var(--card);border:1px solid var(--brd);border-radius:12px;padding:1.2rem;position:relative;overflow:hidden;}}
.sc::before{{content:'';position:absolute;top:0;left:0;right:0;height:3px;}}
.sc:nth-child(1)::before{{background:var(--cyan);}}.sc:nth-child(2)::before{{background:var(--green);}}
.sc:nth-child(3)::before{{background:var(--purple);}}.sc:nth-child(4)::before{{background:var(--amber);}}
.sl{{font-size:.7rem;color:var(--tm);text-transform:uppercase;letter-spacing:.05em;font-weight:600;}}
.sv{{font-size:1.8rem;font-weight:700;font-family:'JetBrains Mono',monospace;margin-top:.2rem;}}
.sc:nth-child(1) .sv{{color:var(--cyan);}}.sc:nth-child(2) .sv{{color:var(--green);}}
.sc:nth-child(3) .sv{{color:var(--purple);}}.sc:nth-child(4) .sv{{color:var(--amber);}}
.sec{{background:var(--card);border:1px solid var(--brd);border-radius:12px;overflow:hidden;backdrop-filter:blur(10px);}}
.sh{{padding:1rem 1.2rem;border-bottom:1px solid var(--brd);display:flex;align-items:center;gap:.5rem;}}
.sh h2{{font-size:1rem;font-weight:600;}}.cnt{{background:rgba(6,182,212,.15);color:var(--cyan);padding:.15rem .6rem;
border-radius:100px;font-size:.75rem;font-weight:600;font-family:'JetBrains Mono',monospace;}}
table{{width:100%;border-collapse:collapse;}}thead th{{padding:.6rem 1rem;text-align:left;font-size:.7rem;font-weight:600;
text-transform:uppercase;letter-spacing:.05em;color:var(--tm);background:rgba(0,0,0,.2);}}
tbody tr{{border-bottom:1px solid rgba(255,255,255,.03);animation:fadeIn .3s ease-out;}}
tbody td{{padding:.6rem 1rem;font-size:.82rem;}}
.pn{{font-family:'JetBrains Mono',monospace;font-weight:600;color:var(--cyan);}}
.b{{display:inline-flex;padding:.15rem .5rem;border-radius:100px;font-size:.65rem;font-weight:600;text-transform:uppercase;}}
.b-o{{background:rgba(16,185,129,.15);color:var(--green);}}.b-s{{background:rgba(139,92,246,.15);color:var(--purple);}}
.b-t{{background:rgba(59,130,246,.15);color:var(--blue);}}.b-sy{{background:rgba(249,115,22,.15);color:#f97316;}}
.b-u{{background:rgba(168,85,247,.15);color:#a855f7;}}
.b-c{{background:rgba(239,68,68,.15);color:var(--red);text-decoration:none;margin:.1rem;}}
.bn{{font-family:'JetBrains Mono',monospace;font-size:.75rem;color:var(--t2);max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}}
.ft{{text-align:center;padding:1.5rem;color:var(--tm);font-size:.75rem;margin-top:1rem;}}
@keyframes fadeIn{{from{{opacity:0;transform:translateY(10px);}}to{{opacity:1;transform:translateY(0);}}}}
@media(max-width:768px){{.sg{{grid-template-columns:repeat(2,1fr);}}}}
</style></head><body><div class="w">
<div class="hd">{logo_img}<h1>CANAVAR</h1><p style="color:var(--t2);font-size:.9rem;">Live Dashboard</p>
<div class="status" id="status">SCANNING...</div></div>
<div class="sg">
<div class="sc"><div class="sl">SCANNED</div><div class="sv" id="s-scn">0</div></div>
<div class="sc"><div class="sl">OPEN PORTS</div><div class="sv" id="s-opn">0</div></div>
<div class="sc"><div class="sl">ELAPSED</div><div class="sv" id="s-time">0.0s</div></div>
<div class="sc"><div class="sl">CVE</div><div class="sv" id="s-cve">0</div></div>
</div>
<div class="sec"><div class="sh"><h2>Live Results</h2><span class="cnt" id="r-cnt">0</span></div>
<table><thead><tr><th>Target</th><th>Port</th><th>Service</th><th>Status</th><th>Banner</th><th>Type</th><th>Latency</th><th>CVE</th></tr></thead>
<tbody id="tbody"></tbody></table></div>
<div class="ft">Canavar Port Scanner v2026 - Real-time Monitoring</div>
</div><script>
const src=new EventSource('/events');let oc=0,cc=0,st=Date.now();
function esc(s){{return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}}
const tmr=setInterval(()=>{{document.getElementById('s-time').textContent=((Date.now()-st)/1000).toFixed(1)+'s';}},100);
src.onmessage=(e)=>{{const ev=JSON.parse(e.data);
if(ev.type==='port_found'){{oc++;const d=ev.data;if(d.cves)cc+=d.cves.length;
document.getElementById('s-opn').textContent=oc;document.getElementById('s-cve').textContent=cc;
document.getElementById('r-cnt').textContent=oc;const tb=document.getElementById('tbody');
const r=document.createElement('tr');
const cb=(d.cves||[]).map(c=>`<a href="https://nvd.nist.gov/vuln/detail/${{c}}" target="_blank" class="b b-c">${{c}}</a>`).join(' ')||'<span style="color:var(--tm)">-</span>';
const lat=d.latency_ms?d.latency_ms.toFixed(1)+'ms':'-';
const st=d.scan_type==='SYN'?'b-sy':(d.scan_type==='UDP'?'b-u':'b-t');
r.innerHTML=`<td class="pn">${{esc(d.target||'-')}}</td><td><span class="pn">${{d.port}}</span></td><td><span class="b b-s">${{esc(d.service)}}</span></td>
<td><span class="b b-o">OPEN</span></td><td class="bn">${{esc((d.banner||'').substring(0,80))||'No banner'}}</td>
<td><span class="b ${{st}}">${{esc(d.scan_type)}}</span></td><td>${{lat}}</td><td>${{cb}}</td>`;
tb.insertBefore(r,tb.firstChild);}}
else if(ev.type==='progress'){{document.getElementById('s-scn').textContent=ev.data.scanned+'/'+ev.data.total;}}
else if(ev.type==='scan_complete'){{clearInterval(tmr);const s=document.getElementById('status');s.textContent='COMPLETE';
s.classList.add('done');s.classList.remove('pulse');src.close();}}
}};</script></body></html>'''


# ── Scan Diff / Comparison ─────────────────────────────────────
def compare_scans(current_data, previous_file):
    """Compare current scan data with a previous scan JSON file.
    Returns dict with new_ports, closed_ports, changed_banners."""
    with open(previous_file, "r", encoding="utf-8") as f:
        prev_data = json.load(f)

    def _build_port_map(scan_data):
        pm = {}
        for td in scan_data.get("targets", []):
            for r in td["results"]:
                key = f"{td.get('ip', td['target'])}:{r['port']}"
                pm[key] = r
        return pm

    prev_map = _build_port_map(prev_data)
    curr_map = _build_port_map(current_data)

    new_ports = []
    for k in sorted(curr_map.keys()):
        if k not in prev_map:
            new_ports.append((k, curr_map[k]))

    closed_ports = []
    for k in sorted(prev_map.keys()):
        if k not in curr_map:
            closed_ports.append((k, prev_map[k]))

    changed = []
    for k in sorted(set(curr_map) & set(prev_map)):
        if curr_map[k].get("banner", "") != prev_map[k].get("banner", ""):
            changed.append((k, prev_map[k], curr_map[k]))

    return {
        "new": new_ports, "closed": closed_ports, "changed": changed,
        "prev_meta": prev_data.get("metadata", {}),
    }


def print_diff_results(diff, lang_code="en"):
    """Print diff results to terminal with colors."""
    L = LANG[lang_code]
    new, closed, changed = diff["new"], diff["closed"], diff["changed"]
    prev_time = diff["prev_meta"].get("end_time", "?")

    cprint(f"\n{'='*50}", C.BOLD)
    cprint(f"  {L['scan_comparison'].format(prev_time=prev_time)}", C.BOLD + C.CYAN)
    cprint(f"{'='*50}", C.BOLD)

    if new:
        cprint(f"\n  [+] {L['new_open_ports']}: {len(new)}", C.GREEN + C.BOLD)
        for key, r in new:
            cprint(f"      + {key} ({r['service']}) - {r.get('banner','')[:50]}", C.GREEN)

    if closed:
        cprint(f"\n  [-] {L['closed_ports_label']}: {len(closed)}", C.RED + C.BOLD)
        for key, r in closed:
            cprint(f"      - {key} ({r['service']})", C.RED)

    if changed:
        cprint(f"\n  [~] {L['changed_banners']}: {len(changed)}", C.YELLOW + C.BOLD)
        for key, old, cur in changed:
            cprint(f"      ~ {key}: '{old.get('banner','')[:40]}' -> '{cur.get('banner','')[:40]}'", C.YELLOW)

    if not new and not closed and not changed:
        cprint(f"\n  {L['no_changes']}", C.DIM)

    cprint(f"\n{'='*50}\n", C.BOLD)


# ── Vulnerability Assessment ──────────────────────────────────
VULN_DB = [
    {"service": "openssh", "min_ver": (0,), "max_ver": (9,7), "cve": "CVE-2024-6387",
     "cvss": 8.1, "severity": "HIGH", "desc": "regreSSHion - RCE via signal handler race"},
    {"service": "openssh", "min_ver": (0,), "max_ver": (9,5), "cve": "CVE-2023-48795",
     "cvss": 5.9, "severity": "MEDIUM", "desc": "Terrapin attack - prefix truncation"},
    {"service": "apache", "min_ver": (2,4,49), "max_ver": (2,4,49), "cve": "CVE-2021-41773",
     "cvss": 7.5, "severity": "HIGH", "desc": "Path traversal and file disclosure"},
    {"service": "apache", "min_ver": (2,4,0), "max_ver": (2,4,59), "cve": "CVE-2024-38475",
     "cvss": 9.1, "severity": "CRITICAL", "desc": "mod_rewrite substitution RCE"},
    {"service": "nginx", "min_ver": (0,), "max_ver": (1,25,5), "cve": "CVE-2024-32760",
     "cvss": 6.5, "severity": "MEDIUM", "desc": "HTTP/3 QUIC vulnerability"},
    {"service": "nginx", "min_ver": (0,), "max_ver": (99,), "cve": "CVE-2023-44487",
     "cvss": 7.5, "severity": "HIGH", "desc": "HTTP/2 Rapid Reset DoS"},
    {"service": "vsftpd", "min_ver": (2,3,4), "max_ver": (2,3,4), "cve": "CVE-2011-2523",
     "cvss": 10.0, "severity": "CRITICAL", "desc": "Backdoor command execution"},
    {"service": "proftpd", "min_ver": (0,), "max_ver": (1,3,7), "cve": "CVE-2019-12815",
     "cvss": 9.8, "severity": "CRITICAL", "desc": "mod_copy arbitrary file copy"},
    {"service": "mysql", "min_ver": (5,), "max_ver": (8,3,0), "cve": "CVE-2024-21008",
     "cvss": 4.4, "severity": "MEDIUM", "desc": "Server optimizer vulnerability"},
    {"service": "redis", "min_ver": (0,), "max_ver": (7,2,4), "cve": "CVE-2024-31449",
     "cvss": 8.8, "severity": "HIGH", "desc": "Lua library heap overflow"},
    {"service": "postgresql", "min_ver": (0,), "max_ver": (16,3), "cve": "CVE-2024-7348",
     "cvss": 7.5, "severity": "HIGH", "desc": "pg_dump arbitrary SQL execution"},
    {"service": "elasticsearch", "min_ver": (0,), "max_ver": (8,9,1), "cve": "CVE-2023-31419",
     "cvss": 6.5, "severity": "MEDIUM", "desc": "StackOverflow DoS via regex"},
    {"service": "mongodb", "min_ver": (0,), "max_ver": (7,0,8), "cve": "CVE-2024-1351",
     "cvss": 8.1, "severity": "HIGH", "desc": "BSON parsing DoS"},
]

VERSION_PATTERNS = [
    (r"OpenSSH[_\s](\d+\.\d+(?:\.\d+)?)", "openssh"),
    (r"Apache/(\d+\.\d+\.\d+)", "apache"),
    (r"nginx/(\d+\.\d+\.\d+)", "nginx"),
    (r"vsftpd\s+(\d+\.\d+\.\d+)", "vsftpd"),
    (r"ProFTPD\s+(\d+\.\d+\.\d+)", "proftpd"),
    (r"(\d+\.\d+\.\d+)-MariaDB", "mysql"),
    (r"MySQL.*?(\d+\.\d+\.\d+)", "mysql"),
    (r"redis_version:(\d+\.\d+\.\d+)", "redis"),
    (r"PostgreSQL\s+(\d+\.\d+)", "postgresql"),
    (r'"number"\s*:\s*"(\d+\.\d+\.\d+)"', "elasticsearch"),
    (r"mongod.*?v(\d+\.\d+\.\d+)", "mongodb"),
]


def _parse_version_tuple(ver_str):
    try:
        return tuple(int(x) for x in ver_str.split("."))
    except Exception:
        return (0,)


def parse_service_version(banner):
    """Extract (service_name, version_string) from banner text."""
    if not banner:
        return None, None
    for pattern, svc in VERSION_PATTERNS:
        m = re.search(pattern, banner, re.IGNORECASE)
        if m:
            return svc, m.group(1)
    return None, None


def assess_vulnerabilities(scan_data):
    """Run vulnerability assessment on scan results. Returns enriched data with vuln info."""
    total_vulns = []
    for td in scan_data.get("targets", []):
        for r in td["results"]:
            svc, ver_str = parse_service_version(r.get("banner", ""))
            if not svc or not ver_str:
                continue
            ver = _parse_version_tuple(ver_str)
            for vuln in VULN_DB:
                if vuln["service"] != svc:
                    continue
                if vuln["min_ver"] <= ver <= vuln["max_ver"]:
                    entry = {
                        "target": td.get("ip", td["target"]),
                        "port": r["port"], "service": svc, "version": ver_str,
                        "cve": vuln["cve"], "cvss": vuln["cvss"],
                        "severity": vuln["severity"], "desc": vuln["desc"],
                    }
                    total_vulns.append(entry)
                    # Add to result's CVE list if not already there
                    if vuln["cve"] not in r.get("cves", []):
                        r.setdefault("cves", []).append(vuln["cve"])
                        r.setdefault("cve_details", []).append((vuln["cve"], vuln["desc"]))
    scan_data["vulnerabilities"] = total_vulns
    return total_vulns


def print_vuln_results(vulns, lang_code="en"):
    """Print vulnerability assessment results to terminal."""
    L = LANG[lang_code]
    if not vulns:
        cprint(f"\n  {L['no_vuln_found']}", C.DIM)
        return

    cprint(f"\n{'='*55}", C.BOLD)
    cprint(f"  {L['vuln_assessment']}", C.BOLD + C.RED)
    cprint(f"{'='*55}", C.BOLD)

    sev_colors = {"CRITICAL": C.RED + C.BOLD, "HIGH": C.RED, "MEDIUM": C.YELLOW, "LOW": C.BLUE}
    for v in vulns:
        color = sev_colors.get(v["severity"], C.RESET)
        cprint(f"\n  [{v['severity']}] {v['cve']} (CVSS: {v['cvss']})", color)
        cprint(f"    {v['target']}:{v['port']} - {v['service']} {v['version']}", C.RESET)
        cprint(f"    {v['desc']}", C.DIM)
        cprint(f"    https://nvd.nist.gov/vuln/detail/{v['cve']}", C.CYAN)

    cprint(f"\n{'='*55}\n", C.BOLD)


# ── Timing Profiles ───────────────────────────────────────────
TIMING_PROFILES = {
    0: {"name": "Paranoid", "threads": 1, "timeout": 5.0, "delay": 5.0},
    1: {"name": "Sneaky", "threads": 5, "timeout": 3.0, "delay": 2.0},
    2: {"name": "Polite", "threads": 10, "timeout": 2.0, "delay": 0.5},
    3: {"name": "Normal", "threads": 200, "timeout": 1.5, "delay": 0.0},
    4: {"name": "Aggressive", "threads": 500, "timeout": 0.8, "delay": 0.0},
    5: {"name": "Insane", "threads": 1000, "timeout": 0.5, "delay": 0.0},
}


# ── Main Entrypoint ────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Canavar Port Scanner v2026 - Cross-Platform Network Recon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python canavar.py -t 192.168.1.1 -p 1-1024
  python canavar.py -t scanme.nmap.org --top-ports 100
  python canavar.py -t 10.0.0.0/24 -p 22,80,443 --lang en
  python canavar.py -t example.com --syn --top-ports 50
  python canavar.py -t 10.0.0.1 --top-ports 100 --dashboard
  python canavar.py -t target.com --top-ports 100 --vuln-scan
  python canavar.py -t server.com -p 1-1024 --diff previous_scan.json
  python canavar.py -t 192.168.1.1 -p 80,443 --udp --udp-ports 53,161
  python canavar.py -t 192.168.1.0/24 --discovery --top-ports 100
  python canavar.py -t target.com --timing 2 --retries 2
  python canavar.py -t target.com --update-cve --nvd-api-key YOUR_KEY"""
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Target IP, hostname, IPv6, or CIDR (e.g. 192.168.1.0/24 or 2001:db8::1)")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Port range: 1-1024, 22,80,443, or 22,80,8000-9000")
    parser.add_argument("--top-ports", type=int, default=None, metavar="N",
                        help=f"Scan top N most common ports (max {len(TOP_PORTS)})")
    parser.add_argument("-th", "--threads", type=int, default=None,
                        help="Number of threads (overridden by timing profile)")
    parser.add_argument("--syn", action="store_true",
                        help="Use SYN (stealth) scan (requires root/admin + scapy)")
    parser.add_argument("--udp", action="store_true",
                        help="Enable UDP scanning")
    parser.add_argument("--udp-ports", default="53,161,123,67,68,69",
                        help="UDP ports to scan (default: DNS, SNMP, NTP, DHCP, TFTP)")
    parser.add_argument("--no-banner", action="store_true",
                        help="Skip banner grabbing (faster)")
    parser.add_argument("-o", "--output", default="scan_result",
                        help="Output filename prefix (default: scan_result)")
    parser.add_argument("--lang", choices=["en", "tr"], default="tr",
                        help="Output language (default: tr)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose error output")
    parser.add_argument("--dashboard", action="store_true",
                        help="Launch live web dashboard during scan")
    parser.add_argument("--dashboard-port", type=int, default=8888, metavar="PORT",
                        help="Dashboard server port (default: 8888)")
    parser.add_argument("--diff", metavar="FILE",
                        help="Compare results with a previous scan JSON file")
    parser.add_argument("--vuln-scan", action="store_true",
                        help="Run version-based vulnerability assessment")
    parser.add_argument("--timeout", type=float, default=None,
                        help="Socket timeout in seconds (overridden by timing profile)")
    parser.add_argument("--timing", "-T", type=int, choices=range(6), metavar="0-5",
                        help="Timing profile: 0=Paranoid, 1=Sneaky, 2=Polite, 3=Normal, 4=Aggressive, 5=Insane")
    parser.add_argument("--retries", type=int, default=0,
                        help="Number of retries for failed connections (default: 0)")
    discovery_group = parser.add_mutually_exclusive_group()
    discovery_group.add_argument("--discovery", action="store_true",
                        help="Enable host discovery before scanning")
    discovery_group.add_argument("--skip-discovery", action="store_true",
                        help="Skip discovery and scan all hosts in CIDR")
    parser.add_argument("--os-detect", action="store_true",
                        help="Attempt OS detection based on TTL analysis")
    parser.add_argument("--update-cve", action="store_true",
                        help="Update CVE database from NVD API")
    parser.add_argument("--nvd-api-key", metavar="KEY",
                        help="NVD API key for higher rate limits")

    args = parser.parse_args()

    lang_code = args.lang
    L = LANG[lang_code]

    # Setup verbose logging
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    # Print banner
    cprint(BANNER_ART, C.CYAN)

    # Apply timing profile if specified
    threads = args.threads or 200
    timeout = args.timeout or 1.5
    delay = 0.0
    if args.timing is not None:
        profile = TIMING_PROFILES[args.timing]
        threads = profile["threads"]
        timeout = profile["timeout"]
        delay = profile["delay"]
        timing_name = profile["name"]
        cprint(f"[*] Timing Profile: -{args.timing} ({timing_name})", C.CYAN)
    else:
        timing_name = None

    # Update CVE database if requested
    global CVE_DATABASE
    if args.update_cve:
        try:
            CVE_DATABASE = update_cve_database(args.nvd_api_key, lang_code)
        except Exception:
            cprint(L["cve_update_failed"], C.YELLOW)

    # SYN scan checks
    use_syn = args.syn
    if use_syn:
        if not HAS_SCAPY:
            cprint(L["syn_no_scapy"], C.YELLOW)
            use_syn = False
        elif not is_admin():
            cprint(L["syn_no_root"], C.YELLOW)
            use_syn = False

    # Resolve targets
    try:
        targets = resolve_targets(args.target)
    except ValueError as e:
        cprint(L["error"].format(msg=str(e)), C.RED)
        sys.exit(1)

    if len(targets) > 1:
        cprint(L["cidr_info"].format(count=len(targets)), C.BLUE)

    # Host discovery
    if args.discovery and not args.skip_discovery and len(targets) > 1:
        cprint("[*] Running host discovery...", C.CYAN)
        targets = discover_hosts(targets, timeout=3)
        total_hosts = len(resolve_targets(args.target))
        cprint(L["discovery_result"].format(alive=len(targets), total=total_hosts), C.BLUE)

    # Parse ports
    try:
        ports = parse_ports(args.ports, args.top_ports)
    except ValueError as e:
        cprint(L["error"].format(msg=str(e)), C.RED)
        sys.exit(1)

    # Parse UDP ports
    udp_ports = None
    if args.udp:
        try:
            udp_ports = parse_ports(args.udp_ports)
        except ValueError as e:
            cprint(L["error"].format(msg=str(e)), C.RED)
            sys.exit(1)

    # Dashboard setup
    dashboard_state = None
    dashboard_server = None
    if args.dashboard:
        dashboard_state = DashboardState()
        dashboard_state.metadata = {"target": args.target, "total_ports": len(ports) + (len(udp_ports) if udp_ports else 0)}
        dashboard_server = start_dashboard(args.dashboard_port, dashboard_state)

    # Scan metadata
    start_time = time.time()
    start_dt = datetime.now()
    scan_type_str = "SYN Stealth" if use_syn else "TCP Connect"
    if args.udp:
        scan_type_str += " + UDP"

    scan_data = {
        "metadata": {
            "tool": "Canavar Port Scanner v2026",
            "target": args.target,
            "targets_display": args.target,
            "port_spec": args.ports if not args.top_ports else f"top-{args.top_ports}",
            "total_ports": len(ports) + (len(udp_ports) if udp_ports else 0),
            "scan_type": scan_type_str,
            "threads": threads,
            "timeout": timeout,
            "timing_profile": timing_name or "Custom",
            "retries": args.retries,
            "start_time": start_dt.isoformat(),
        },
        "targets": [],
    }

    # Run scans
    try:
        for display_name, ip, is_ipv6 in targets:
            cprint(f"\n{L['scanning_target'].format(target=display_name)} ({ip})", C.BOLD + C.BLUE)
            cprint(L["scan_started"].format(
                target=ip, time=datetime.now().strftime("%H:%M:%S")
            ), C.YELLOW)

            if dashboard_state:
                dashboard_state.add_event("scan_start", {
                    "target": display_name, "ip": ip, "total_ports": len(ports) + (len(udp_ports) if udp_ports else 0)
                })

            results = run_scan(
                target_ip=ip, target_name=display_name, ports=ports,
                threads=threads, use_syn=use_syn, lang_code=lang_code,
                no_banner=args.no_banner, dashboard_state=dashboard_state,
                timeout=timeout, udp_ports=udp_ports, is_ipv6=is_ipv6,
                retries=args.retries, delay=delay
            )

            # OS Detection
            os_detection = None
            if args.os_detect:
                os_detection = os_fingerprint(ip, port=80, timeout=timeout, is_ipv6=is_ipv6)
                if os_detection:
                    cprint(f"[*] OS Detection: {os_detection}", C.CYAN)

            scan_data["targets"].append({
                "target": display_name, "ip": ip,
                "results": results, "open_count": len(results),
                "os_detection": os_detection or "Unknown",
            })

    except KeyboardInterrupt:
        cprint(L["interrupted"], C.RED)

    # Stop dashboard SSE
    if dashboard_state:
        dashboard_state.is_running = False
        time.sleep(0.5)
        if dashboard_state:
            dashboard_state.add_event("scan_complete", {})

    # Finalize metadata
    end_time = time.time()
    elapsed = round(end_time - start_time, 2)
    scan_data["metadata"]["end_time"] = datetime.now().isoformat()
    scan_data["metadata"]["duration_seconds"] = elapsed

    total_open = sum(t["open_count"] for t in scan_data["targets"])
    cprint(f"\n{L['scan_finished'].format(count=total_open, elapsed=elapsed)}", C.GREEN + C.BOLD)

    # Vulnerability Assessment
    if args.vuln_scan:
        vulns = assess_vulnerabilities(scan_data)
        print_vuln_results(vulns, lang_code)

    # Export results
    export_json(scan_data, args.output)
    export_csv(scan_data, args.output)
    html_path = export_html(scan_data, args.output, lang_code)

    files = f"{args.output}.json, {args.output}.csv, {args.output}.html"
    cprint(L["results_saved"].format(files=files), C.YELLOW)

    # Scan Diff
    if args.diff:
        if os.path.exists(args.diff):
            diff = compare_scans(scan_data, args.diff)
            print_diff_results(diff, lang_code)
        else:
            cprint(L["error"].format(msg=f"Diff file not found: {args.diff}"), C.RED)

    # Keep dashboard alive if running
    if dashboard_server:
        if lang_code == "tr":
            cprint("[*] Dashboard aktif. Kapatmak icin Ctrl+C basin.", C.CYAN)
        else:
            cprint("[*] Dashboard is running. Press Ctrl+C to stop.", C.CYAN)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            cprint("\n[*] Dashboard stopped.", C.DIM)
            dashboard_server.shutdown()


if __name__ == "__main__":
    main()
