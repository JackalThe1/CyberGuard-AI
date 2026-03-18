"""
CyberGuard AI  -  AI-Powered IPS + IDS Engine
Autonomous threat detection, classification, and response.
Covers: DDoS/DoS, SQLi, XSS, RCE, LFI/RFI, SSRF, Path Traversal,
        Brute Force, Credential Stuffing, Scanners, Bot Nets,
        Log4Shell, ShellShock, XXE, IDOR, and more.
"""

import os, sys, re, json, sqlite3, time, threading, queue
import smtplib, platform, io, math, secrets, hashlib
from datetime import datetime, timedelta
from collections import defaultdict, deque
from pathlib import Path
from dotenv import load_dotenv
from flask import Flask, request, jsonify, send_from_directory, Response, send_file, session
from flask_cors import CORS

# ── Boot ──────────────────────────────────────────────────────────────────────
load_dotenv()
os.chdir(Path(__file__).resolve().parent)

app = Flask(__name__, static_folder="static")
CORS(app, supports_credentials=True)

# ── Secret key (generated once, persisted so sessions survive restart) ────────
_SECRET_FILE = Path("data/.secret_key")
_SECRET_FILE.parent.mkdir(exist_ok=True)
if _SECRET_FILE.exists():
    app.secret_key = _SECRET_FILE.read_bytes()
else:
    app.secret_key = secrets.token_bytes(32)
    _SECRET_FILE.write_bytes(app.secret_key)

# ── Auth store ────────────────────────────────────────────────────────────────
AUTH_PATH = Path("data/auth.json")

def _hash_password(password: str, salt: str = "") -> str:
    """PBKDF2-HMAC-SHA256 — 260,000 iterations."""
    if not salt:
        salt = secrets.token_hex(32)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return f"{salt}${key.hex()}"

def _verify_password(password: str, stored: str) -> bool:
    try:
        salt, _ = stored.split("$", 1)
        return secrets.compare_digest(stored, _hash_password(password, salt))
    except Exception:
        return False

def auth_needs_setup() -> bool:
    return not AUTH_PATH.exists()

def auth_get() -> dict:
    if AUTH_PATH.exists():
        try:
            return json.loads(AUTH_PATH.read_text())
        except Exception:
            pass
    return {}

def auth_save(username: str, password: str):
    AUTH_PATH.write_text(json.dumps({
        "username":      username,
        "password_hash": _hash_password(password),
        "created_at":    datetime.now().isoformat(),
    }, indent=2))

# ── Login rate limiter ────────────────────────────────────────────────────────
_LOGIN_ATTEMPTS: dict = defaultdict(list)   # ip -> [timestamps]
_LOGIN_LOCK = threading.Lock()
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW = 60   # seconds

def _login_allowed(ip: str) -> tuple[bool, int]:
    """Return (allowed, seconds_until_reset)."""
    now = time.time()
    with _LOGIN_LOCK:
        attempts = _LOGIN_ATTEMPTS[ip]
        attempts[:] = [t for t in attempts if now - t < LOGIN_WINDOW]
        if len(attempts) >= MAX_LOGIN_ATTEMPTS:
            wait = int(LOGIN_WINDOW - (now - attempts[0])) + 1
            return False, wait
        attempts.append(now)
        return True, 0

# ── Auth middleware ───────────────────────────────────────────────────────────
PUBLIC_ROUTES = {"/", "/api/auth/status", "/api/auth/login",
                 "/api/auth/setup", "/api/health"}

@app.before_request
def require_auth():
    # Enforce IPS block list first
    if CFG.get("ips_mode", True):
        client_ip = request.remote_addr or ""
        if is_blocked(client_ip):
            info = BLOCKED_IPS[client_ip]
            return jsonify({"blocked": True, "reason": info["reason"],
                            "message": "Your IP has been blocked by CyberGuard AI IPS."}), 403
    # Only guard API routes
    if not request.path.startswith("/api/"):
        return
    if request.path in PUBLIC_ROUTES:
        return
    if auth_needs_setup():
        return jsonify({"error": "setup_required"}), 401
    if not session.get("authenticated"):
        return jsonify({"error": "unauthorized"}), 401

# ── Config ────────────────────────────────────────────────────────────────────
CONFIG_PATH = Path("data/config.json")
CONFIG_PATH.parent.mkdir(exist_ok=True)

def load_config():
    defaults = {
        "groq_api_key":           os.getenv("GROQ_API_KEY", ""),
        "slack_webhook":          os.getenv("SLACK_WEBHOOK_URL", ""),
        "discord_webhook":        os.getenv("DISCORD_WEBHOOK_URL", ""),
        "email_host":             os.getenv("EMAIL_HOST", "smtp.gmail.com"),
        "email_port":             int(os.getenv("EMAIL_PORT", "587")),
        "email_user":             os.getenv("EMAIL_USER", ""),
        "email_pass":             os.getenv("EMAIL_PASS", ""),
        "email_from":             os.getenv("EMAIL_FROM", ""),
        "email_to":               os.getenv("EMAIL_TO", ""),
        "monitor_log_path":       os.getenv("MONITOR_LOG_PATH", ""),
        "auto_block_threshold":   7,
        "ddos_rps_threshold":     50,
        "ddos_window_seconds":    10,
        "max_analyze_per_upload": 50,
        "ips_mode":               True,
    }
    if CONFIG_PATH.exists():
        try:
            defaults.update(json.loads(CONFIG_PATH.read_text()))
        except Exception:
            pass
    return defaults

def save_config(cfg):
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))

CFG = load_config()

# ── Active block list (IPS in-memory) ─────────────────────────────────────────
# ip -> {"reason": str, "blocked_at": datetime, "threat_type": str, "severity": int}
BLOCKED_IPS: dict = {}
BLOCK_LOCK   = threading.Lock()

def block_ip(ip: str, reason: str, threat_type: str, severity: int):
    with BLOCK_LOCK:
        BLOCKED_IPS[ip] = {
            "ip":           ip,
            "reason":       reason,
            "threat_type":  threat_type,
            "severity":     severity,
            "blocked_at":   datetime.now().isoformat(),
        }

def is_blocked(ip: str) -> bool:
    return ip in BLOCKED_IPS

# ── Flask before_request: IPS block list is enforced inside require_auth above ─

# ── DDoS / DoS tracker ────────────────────────────────────────────────────────
# ip -> deque of timestamps within sliding window
_REQUEST_TIMESTAMPS: dict = defaultdict(lambda: deque())
_DDOS_LOCK = threading.Lock()

def record_request(ip: str) -> dict | None:
    """Record a request; return DDoS alert dict if threshold exceeded, else None."""
    if not ip:
        return None
    window = int(CFG.get("ddos_window_seconds", 10))
    threshold = int(CFG.get("ddos_rps_threshold", 50))
    now = time.time()
    with _DDOS_LOCK:
        dq = _REQUEST_TIMESTAMPS[ip]
        dq.append(now)
        cutoff = now - window
        while dq and dq[0] < cutoff:
            dq.popleft()
        count = len(dq)
    if count >= threshold:
        return {
            "ip":         ip,
            "count":      count,
            "window":     window,
            "rps":        round(count / window, 1),
            "timestamp":  datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000"),
            "method":     "FLOOD",
            "path":       "/*",
            "status":     "—",
            "user_agent": "Unknown",
            "reasons":    [f"DDoS/DoS: {count} requests in {window}s ({round(count/window,1)} req/s)"],
            "threat_type":"ddos",
            "raw_log":    f"[LIVE] {ip} - {count} requests in {window}s - VOLUMETRIC FLOOD DETECTED",
        }
    return None

# ── Groq client ───────────────────────────────────────────────────────────────
def get_groq():
    k = CFG.get("groq_api_key", "")
    if not k or k == "your_groq_api_key_here":
        return None
    try:
        from groq import Groq
        return Groq(api_key=k)
    except Exception:
        return None

# ── Database ──────────────────────────────────────────────────────────────────
DB_PATH = Path("data/threats.db")

def init_db():
    with sqlite3.connect(str(DB_PATH)) as con:
        con.execute("""CREATE TABLE IF NOT EXISTS threats(
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT,
            ip_address      TEXT,
            threat_type     TEXT,
            severity        INTEGER,
            confidence      INTEGER,
            reasoning       TEXT,
            attack_vector   TEXT,
            potential_impact TEXT,
            mitre_tactic    TEXT,
            cve_reference   TEXT,
            raw_log         TEXT,
            log_source      TEXT DEFAULT 'upload',
            firewall_command TEXT,
            actions_taken   TEXT,
            alert_sent      INTEGER DEFAULT 0,
            blocked         INTEGER DEFAULT 0
        )""")
        con.commit()

init_db()

def db_insert(d):
    with sqlite3.connect(str(DB_PATH)) as con:
        con.execute("""INSERT INTO threats
            (timestamp,ip_address,threat_type,severity,confidence,reasoning,
             attack_vector,potential_impact,mitre_tactic,cve_reference,
             raw_log,log_source,firewall_command,actions_taken,alert_sent,blocked)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (d["timestamp"],d["ip_address"],d["threat_type"],d["severity"],
             d["confidence"],d["reasoning"],d["attack_vector"],
             d.get("potential_impact",""),d.get("mitre_tactic",""),
             d.get("cve_reference",""),d["raw_log"],
             d.get("log_source","upload"),d.get("firewall_command",""),
             json.dumps(d.get("actions_taken",[])),
             1 if d.get("alert_sent") else 0,
             1 if d.get("blocked") else 0))
        con.commit()

def db_all():
    with sqlite3.connect(str(DB_PATH)) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute("SELECT * FROM threats ORDER BY timestamp DESC").fetchall()
    out = []
    for r in rows:
        t = dict(r)
        try: t["actions_taken"] = json.loads(t["actions_taken"])
        except: t["actions_taken"] = []
        out.append(t)
    return out

def db_clear():
    with sqlite3.connect(str(DB_PATH)) as con:
        con.execute("DELETE FROM threats"); con.commit()

# ── Platform detection ────────────────────────────────────────────────────────
def get_platform():
    s = platform.system()
    info = {
        "raw":          sys.platform,
        "system":       s,
        "hostname":     platform.node(),
        "machine":      platform.machine(),
        "architecture": platform.architecture()[0],
        "processor":    platform.processor() or platform.machine(),
        "python_version": platform.python_version(),
        "display":      s,
        "os_detail":    s,
        "kernel":       platform.release(),
    }
    if s == "Windows":
        _, ver, _, ptype = platform.win32_ver()
        build = ver.split(".")[-1] if ver else "0"
        try:    name = "Windows 11" if int(build) >= 22000 else f"Windows {platform.win32_ver()[0]}"
        except: name = "Windows"
        info.update({"display": name, "os_detail": f"{name} Build {build} {ptype}".strip()})
    elif s == "Darwin":
        v = platform.mac_ver()[0]
        names = {"15":"macOS Sequoia","14":"macOS Sonoma","13":"macOS Ventura",
                 "12":"macOS Monterey","11":"macOS Big Sur"}
        nm = names.get(v.split(".")[0], "macOS")
        arch = "Apple Silicon" if platform.machine() == "arm64" else "Intel"
        info.update({"display": f"{nm} {v}", "os_detail": f"{nm} {v} ({arch})"})
    elif s == "Linux":
        pretty = ""
        for src in ["/etc/os-release", "/usr/lib/os-release"]:
            try:
                kv = dict(l.strip().split("=",1) for l in open(src) if "=" in l)
                pretty = kv.get("PRETTY_NAME","").strip('"')
                if pretty: break
            except: pass
        if not pretty:
            try: pretty = platform.freedesktop_os_release().get("PRETTY_NAME","Linux")
            except: pretty = "Linux"
        info.update({"display": pretty, "os_detail": f"{pretty} (kernel {platform.release()})"})
    return info

# ── Firewall commands ─────────────────────────────────────────────────────────
def fw_cmds(ip):
    return {
        "linux_ufw":          f"sudo ufw deny from {ip} to any",
        "linux_iptables":     f"sudo iptables -I INPUT 1 -s {ip} -j DROP && sudo iptables -I OUTPUT 1 -d {ip} -j DROP",
        "linux_nftables":     f"sudo nft add rule inet filter input ip saddr {ip} drop",
        "macos_pf":           f"echo 'block drop from {ip}' | sudo pfctl -ef -",
        "windows_firewall":   f'netsh advfirewall firewall add rule name="CyberGuard-Block-{ip}" dir=in action=block remoteip={ip} enable=yes',
        "windows_powershell": f"New-NetFirewallRule -DisplayName 'CyberGuard Block {ip}' -Direction Inbound -RemoteAddress {ip} -Action Block -Enabled True",
        "windows_defender":   f'Add-MpPreference -ExclusionIpAddress "{ip}"  # Then block via firewall',
        "cisco_acl":          f"ip access-list extended CYBERGUARD\n deny ip host {ip} any\n permit ip any any",
        "palo_alto":          f"set address CG-Block-{ip.replace('.','_')} ip-netmask {ip}/32\nset address-group CyberGuard-Blocklist static CG-Block-{ip.replace('.','_')}",
        "nginx_block":        f'# Add to /etc/nginx/conf.d/blocklist.conf:\ndeny {ip};',
        "apache_block":       f'# Add to .htaccess or httpd.conf:\nRequire not ip {ip}',
        "haproxy":            f'# Add to HAProxy ACL:\nacl blocked_ip src {ip}\nhttp-request deny if blocked_ip',
    }

# ═══════════════════════════════════════════════════════════════════════════════
# THREAT SIGNATURES  -  Comprehensive IDS ruleset
# ═══════════════════════════════════════════════════════════════════════════════
SIGNATURES = [
    # ── Remote Code Execution ──────────────────────────────────────────────────
    (re.compile(r'\$\{jndi:(ldap|rmi|dns|corba|iiop)://', re.I),
     "rce", "Log4Shell (CVE-2021-44228) JNDI injection", 10, "CVE-2021-44228"),
    (re.compile(r'\(\)\s*\{[^}]*\};\s*(bash|sh|ksh|zsh)', re.I),
     "rce", "Shellshock (CVE-2014-6271) exploit attempt", 10, "CVE-2014-6271"),
    (re.compile(r';?\s*(wget|curl|fetch)\s+https?://', re.I),
     "rce", "Remote file download via OS command injection", 10, ""),
    (re.compile(r'(eval|exec|system|passthru|shell_exec|popen|proc_open)\s*\(', re.I),
     "rce", "PHP dangerous function call injection", 9, ""),
    (re.compile(r'\|\s*(id|whoami|uname|cat\s+/etc|ls\s+-|rm\s+-|nc\s+|ncat\s+)', re.I),
     "rce", "Unix command injection via pipe", 9, ""),
    (re.compile(r'(`[^`]+`|\$\([^)]+\))', re.I),
     "rce", "Command substitution injection", 9, ""),
    (re.compile(r'(meterpreter|msfconsole|msf>|payload\.exe)', re.I),
     "rce", "Metasploit framework payload detected", 10, ""),
    (re.compile(r'(base64_decode|gzinflate|str_rot13)\s*\(.*\)', re.I),
     "rce", "Obfuscated PHP code execution", 9, ""),

    # ── SQL Injection ──────────────────────────────────────────────────────────
    (re.compile(r'\bunion\b.{0,30}\bselect\b', re.I),
     "sql_injection", "UNION SELECT extraction attack", 9, ""),
    (re.compile(r"(drop|truncate)\s+(table|database|schema)\s+\w", re.I),
     "sql_injection", "Destructive SQL statement (DROP/TRUNCATE)", 10, ""),
    (re.compile(r'\b(and|or)\b\s+[\d\"\']\s*=\s*[\d\"\']\s*(-{2}|#|\/\*)', re.I),
     "sql_injection", "Boolean-based SQL injection", 8, ""),
    (re.compile(r"\b(and|or)\b.{0,20}sleep\s*\(\d+\)", re.I),
     "sql_injection", "Time-based blind SQL injection (SLEEP)", 9, ""),
    (re.compile(r"waitfor\s+delay\s+['\"]", re.I),
     "sql_injection", "MSSQL time-based blind injection (WAITFOR)", 9, ""),
    (re.compile(r"benchmark\s*\(\s*\d+\s*,", re.I),
     "sql_injection", "MySQL time-based blind injection (BENCHMARK)", 9, ""),
    (re.compile(r"(load_file|into\s+outfile|into\s+dumpfile)", re.I),
     "sql_injection", "SQL file read/write attack", 10, ""),
    (re.compile(r"information_schema\.(tables|columns|schemata)", re.I),
     "sql_injection", "SQL schema enumeration via information_schema", 8, ""),
    (re.compile(r"(char|nchar|varchar)\s*\(\s*\d+", re.I),
     "sql_injection", "SQL char encoding evasion technique", 7, ""),
    (re.compile(r"exec(\s+|\()(\s*xp_cmdshell|\s*sp_)", re.I),
     "sql_injection", "MSSQL stored procedure abuse (xp_cmdshell)", 10, ""),

    # ── XSS ────────────────────────────────────────────────────────────────────
    (re.compile(r'<script[\s>][^<]*?(alert|fetch|document\.cookie|window\.location)', re.I),
     "xss", "Reflected XSS - script tag with payload", 8, ""),
    (re.compile(r'javascript\s*:', re.I),
     "xss", "XSS via javascript: protocol", 8, ""),
    (re.compile(r'on(load|error|click|mouseover|focus|blur|input|change)\s*=\s*["\']?\s*(alert|eval|fetch|document)', re.I),
     "xss", "DOM XSS via event handler injection", 8, ""),
    (re.compile(r'<(img|svg|body|iframe|input)[^>]+on\w+\s*=', re.I),
     "xss", "XSS via HTML attribute injection", 7, ""),
    (re.compile(r'<iframe[^>]+(src|srcdoc)\s*=', re.I),
     "xss", "XSS/Clickjacking via iframe injection", 7, ""),
    (re.compile(r'expression\s*\(|vbscript\s*:', re.I),
     "xss", "Legacy XSS via CSS expression or VBScript", 8, ""),

    # ── Local / Remote File Inclusion ──────────────────────────────────────────
    (re.compile(r'(\.\.[\\/]){2,}', re.I),
     "path_traversal", "Directory traversal attack (../)", 8, ""),
    (re.compile(r'(%2e%2e|%2f%2e|\.\.%2f|%2e\.[\\/])', re.I),
     "path_traversal", "URL-encoded path traversal", 8, ""),
    (re.compile(r'(etc/passwd|etc/shadow|etc/hosts|windows/system32|boot\.ini|win\.ini)', re.I),
     "lfi", "Local File Inclusion - sensitive OS file access", 9, ""),
    (re.compile(r'/proc/(self|[0-9]+)/(environ|cmdline|maps|mem)', re.I),
     "lfi", "LFI via Linux /proc filesystem", 9, ""),
    (re.compile(r'(php://filter|php://input|data://text|zip://)', re.I),
     "lfi", "PHP wrapper LFI/RFI via stream wrapper", 9, ""),
    (re.compile(r'(https?|ftp)://[^/]+/.*\.(php|asp|aspx|jsp|cgi)', re.I),
     "rfi", "Remote File Inclusion - external script execution", 10, ""),

    # ── SSRF ───────────────────────────────────────────────────────────────────
    (re.compile(r'169\.254\.169\.254', re.I),
     "ssrf", "SSRF - AWS/EC2 metadata endpoint access", 9, ""),
    (re.compile(r'(metadata\.google\.internal|169\.254\.170\.2)', re.I),
     "ssrf", "SSRF - GCP/ECS metadata endpoint access", 9, ""),
    (re.compile(r'(localhost|127\.[0-9]+\.[0-9]+\.[0-9]+|::1)', re.I),
     "ssrf", "SSRF - localhost/loopback access attempt", 8, ""),
    (re.compile(r'(gopher|dict|ftp|sftp|smb)://', re.I),
     "ssrf", "SSRF via alternative protocol scheme", 9, ""),
    (re.compile(r'0\.0\.0\.0|0x7f000001|0177\.0\.0\.1', re.I),
     "ssrf", "SSRF - encoded localhost bypass", 8, ""),

    # ── XXE ────────────────────────────────────────────────────────────────────
    (re.compile(r'<!ENTITY\s+\w+\s+SYSTEM\s*["\']', re.I),
     "xxe", "XXE - External Entity injection in XML", 9, ""),
    (re.compile(r'<!DOCTYPE[^>]+\[', re.I),
     "xxe", "XXE - DOCTYPE with inline entity definition", 8, ""),

    # ── Reconnaissance / Scanning ──────────────────────────────────────────────
    (re.compile(r'\.(env|git|svn|hg|DS_Store|htaccess|htpasswd|npmrc|dockerenv)', re.I),
     "reconnaissance", "Hidden/config file enumeration probe", 6, ""),
    (re.compile(r'(wp-config|config\.php|settings\.py|database\.yml|application\.yml|secrets\.json|\.aws/credentials)', re.I),
     "reconnaissance", "Application configuration file probe", 7, ""),
    (re.compile(r'phpinfo\(\)|/server-status|/server-info|/nginx_status|/_cat/indices', re.I),
     "reconnaissance", "Server information disclosure probe", 6, ""),
    (re.compile(r'\.(bak|backup|old|orig|save|swp|tmp|copy|1|2)\b', re.I),
     "reconnaissance", "Backup file enumeration probe", 5, ""),
    (re.compile(r'/(admin|administrator|phpmyadmin|adminer|cpanel|webmin|plesk|directadmin)', re.I),
     "reconnaissance", "Admin panel discovery scan", 5, ""),
    (re.compile(r'(robots\.txt|sitemap\.xml|crossdomain\.xml|clientaccesspolicy\.xml)', re.I),
     "reconnaissance", "Site mapping / policy file access", 3, ""),

    # ── Credential Attacks ─────────────────────────────────────────────────────
    (re.compile(r'/etc/(shadow|gshadow|master\.passwd)', re.I),
     "credential_access", "Credential file direct access attempt", 10, ""),
    (re.compile(r'(credential|password|passwd|secret|token|api_key)\s*=\s*\S+', re.I),
     "credential_access", "Credential exposure in request parameters", 8, ""),

    # ── Web Shell / Backdoor ───────────────────────────────────────────────────
    (re.compile(r'(c99|r57|b374k|wso|webshell|filesman|adminer)', re.I),
     "webshell", "Known web shell tool name detected", 10, ""),
    (re.compile(r'cmd=|command=|exec=|shell=|payload=', re.I),
     "webshell", "Web shell command parameter detected", 8, ""),

    # ── Protocol / Log4j variants ──────────────────────────────────────────────
    (re.compile(r'\$\{(lower|upper|::-|::[a-z])', re.I),
     "rce", "Log4j obfuscation bypass attempt", 10, "CVE-2021-44228"),

    # ── Cryptominer / Malware delivery ────────────────────────────────────────
    (re.compile(r'(xmrig|minerd|stratum\+tcp|monero|coinhive)', re.I),
     "malware_delivery", "Cryptominer indicator detected", 8, ""),
    (re.compile(r'\.(exe|bat|cmd|ps1|vbs|scr|pif)\s*HTTP', re.I),
     "malware_delivery", "Malicious binary download attempt", 9, ""),
]

# User-Agent blacklist
MALICIOUS_UA = [
    "sqlmap","nikto","nmap","masscan","zgrab","nuclei","hydra","medusa",
    "metasploit","burpsuite","havij","acunetix","nessus","openvas","zap",
    "dirbuster","gobuster","wfuzz","ffuf","feroxbuster","dirb","wapiti",
    "skipfish","arachni","w3af","vega","appscan","webinspect","nexpose",
    "python-requests","go-http-client","libwww-perl","lwp-request",
    "curl/","wget/","scrapy","urllib","java/","okhttp","python/",
    "xrumer","harvester","zgrab2","shodan","censys","binaryedge",
]

def parse_line(line: str) -> dict | None:
    """Parse one log line; return event dict or None if benign."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    ip = ts = method = path = status = ua = "-"

    # Apache/Nginx combined log
    m = re.match(
        r'(\S+)\s+\S+\s+\S+\s+\[(.*?)\]\s+"(\S+)\s+(.*?)\s+\S+"\s+(\d+)\s+\S+'
        r'(?:\s+"[^"]*"\s+"([^"]*)")?', line)
    if m:
        ip, ts, method, path, status, ua = (m.group(i) or "-" for i in range(1,7))
    else:
        parts = line.split()
        if parts: ip = parts[0]

    reasons, threat_type, sev_override, cve = [], None, None, ""
    scan_str = f"{path} {ua}"

    # Auth failure
    if status in ("401", "403"):
        reasons.append(f"HTTP {status} access/auth failure")

    # Signature scan
    for sig, ttype, label, base_sev, cve_ref in SIGNATURES:
        if sig.search(scan_str):
            reasons.append(label)
            if threat_type is None:
                threat_type = ttype
                sev_override = base_sev
                cve = cve_ref
            break

    # Malicious UA
    ual = ua.lower()
    for bad in MALICIOUS_UA:
        if bad in ual:
            reasons.append(f"Attack tool detected: {ua[:80]}")
            if threat_type is None:
                threat_type = "malicious_scanner"
                sev_override = 6
            break

    if not reasons:
        return None

    return {
        "ip":           ip,
        "timestamp":    ts,
        "method":       method,
        "path":         path,
        "status":       status,
        "user_agent":   ua,
        "reasons":      reasons,
        "threat_type":  threat_type or "unknown",
        "sev_override": sev_override,
        "cve":          cve,
        "raw_log":      line,
    }

def parse_content(content: str) -> list:
    events = []
    ip_counts: dict = defaultdict(int)
    for line in content.splitlines():
        ev = parse_line(line)
        if ev:
            ip_counts[ev["ip"]] += 1
            events.append(ev)

    # Brute-force tagging
    for ev in events:
        cnt = ip_counts[ev["ip"]]
        if cnt >= 5 and not any("brute" in r.lower() or "ddos" in r.lower() for r in ev["reasons"]):
            ev["reasons"].insert(0, f"Brute force: {cnt} requests from {ev['ip']}")
            if ev["threat_type"] in ("unknown", "reconnaissance"):
                ev["threat_type"] = "brute_force"
                ev["sev_override"] = max(ev.get("sev_override") or 0, 8)

    return events

# ── AI analysis ───────────────────────────────────────────────────────────────
MITRE_MAP = {
    "rce":               ("Execution",             "T1059"),
    "sql_injection":     ("Initial Access",        "T1190"),
    "xss":               ("Defense Evasion",       "T1027"),
    "path_traversal":    ("Discovery",             "T1083"),
    "lfi":               ("Collection",            "T1005"),
    "rfi":               ("Execution",             "T1059"),
    "ssrf":              ("Discovery",             "T1046"),
    "xxe":               ("Initial Access",        "T1190"),
    "reconnaissance":    ("Reconnaissance",        "T1595"),
    "brute_force":       ("Credential Access",     "T1110"),
    "credential_access": ("Credential Access",     "T1552"),
    "webshell":          ("Persistence",           "T1505.003"),
    "malicious_scanner": ("Reconnaissance",        "T1595.002"),
    "ddos":              ("Impact",                "T1498"),
    "malware_delivery":  ("Resource Development",  "T1608"),
}

def analyze(event: dict) -> dict:
    client = get_groq()
    if client:
        result = _ai_analyze(client, event)
        if result:
            return result
    return _heuristic(event)

def _ai_analyze(client, event: dict) -> dict | None:
    prompt = f"""You are a senior threat analyst with MITRE ATT&CK expertise.
Analyze this security event and return ONLY valid JSON — no markdown.

IP: {event['ip']}
Time: {event['timestamp']}
Method: {event['method']}
Path: {event['path']}
Status: {event['status']}
User-Agent: {event['user_agent']}
Detections: {"; ".join(event['reasons'])}

Return exactly this JSON structure:
{{
  "threat_type": "ddos|brute_force|sql_injection|xss|rce|lfi|rfi|path_traversal|ssrf|xxe|reconnaissance|credential_access|webshell|malicious_scanner|malware_delivery|dos|other",
  "severity": <1-10 integer>,
  "confidence": <0-100 integer>,
  "reasoning": "<2-3 sentence technical analysis>",
  "attack_vector": "<precise technical mechanism>",
  "recommended_action": "block_ip|alert_team|monitor|ignore",
  "potential_impact": "<specific business and data risk>",
  "mitre_tactic": "<ATT&CK tactic>",
  "mitre_technique": "<T-number>",
  "cve_reference": "<CVE-XXXX-XXXXX or empty>",
  "ioc_type": "<ip|url|useragent|pattern>",
  "kill_chain_phase": "<reconnaissance|weaponization|delivery|exploitation|installation|c2|actions>"
}}"""
    try:
        resp = client.chat.completions.create(
            model="llama-3.1-70b-versatile",
            messages=[{"role":"user","content":prompt}],
            temperature=0.1, max_tokens=600)
        raw = resp.choices[0].message.content.strip()
        raw = raw.replace("```json","").replace("```","").strip()
        return json.loads(raw)
    except Exception as e:
        print(f"AI error: {e}")
        return None

def _heuristic(event: dict) -> dict:
    tt = event.get("threat_type","unknown")
    base = {
        "rce":10,"lfi":9,"rfi":10,"sql_injection":9,"xxe":9,"ssrf":8,
        "webshell":10,"credential_access":8,"xss":7,"path_traversal":7,
        "brute_force":8,"ddos":9,"dos":8,"malicious_scanner":6,
        "reconnaissance":5,"malware_delivery":9,
    }
    sev = event.get("sev_override") or base.get(tt, 5)
    rec = "block_ip" if sev >= 7 else "alert_team"
    mt = MITRE_MAP.get(tt, ("Unknown",""))
    return {
        "threat_type":     tt,
        "severity":        sev,
        "confidence":      72,
        "reasoning":       "Heuristic IDS detection: " + "; ".join(event.get("reasons",[])),
        "attack_vector":   "Matched against CyberGuard IDS signature database",
        "recommended_action": rec,
        "potential_impact":"System compromise, data exfiltration, or service disruption",
        "mitre_tactic":    mt[0],
        "mitre_technique": mt[1],
        "cve_reference":   event.get("cve",""),
        "ioc_type":        "ip",
        "kill_chain_phase":"exploitation",
    }

# ── Decision / Response engine (IPS) ─────────────────────────────────────────
def decide(event: dict, analysis: dict, source: str = "upload") -> dict:
    sev   = analysis.get("severity", 5)
    rec   = analysis.get("recommended_action","monitor")
    ip    = event["ip"]
    cfg   = CFG
    threshold = int(cfg.get("auto_block_threshold", 7))

    actions, fw, sent, blocked_flag = [], {}, False, False

    if sev >= threshold or rec == "block_ip":
        fw = fw_cmds(ip)
        if cfg.get("ips_mode", True):
            block_ip(ip, analysis.get("reasoning",""), analysis.get("threat_type",""), sev)
            actions.append(f"IPS BLOCKED: {ip} added to active block list")
        actions.append("Firewall remediation commands generated (all platforms)")
        blocked_flag = True
        _dispatch_alerts(event, analysis, "HIGH")
        sent = True
        actions.append("HIGH priority alert dispatched")

    elif sev >= 4 or rec == "alert_team":
        _dispatch_alerts(event, analysis, "MEDIUM")
        sent = True
        actions.append("MEDIUM priority alert dispatched")
    else:
        actions.append("Logged — added to watchlist")

    record = {
        "timestamp":        datetime.now().isoformat(),
        "ip_address":       ip,
        "threat_type":      analysis.get("threat_type","unknown"),
        "severity":         sev,
        "confidence":       analysis.get("confidence",0),
        "reasoning":        analysis.get("reasoning",""),
        "attack_vector":    analysis.get("attack_vector",""),
        "potential_impact": analysis.get("potential_impact",""),
        "mitre_tactic":     analysis.get("mitre_tactic",""),
        "cve_reference":    analysis.get("cve_reference",""),
        "raw_log":          event.get("raw_log",""),
        "log_source":       source,
        "firewall_command": json.dumps(fw) if fw else "",
        "actions_taken":    actions,
        "alert_sent":       sent,
        "blocked":          blocked_flag,
    }
    db_insert(record)
    return record

# ── Alerts ────────────────────────────────────────────────────────────────────
def _dispatch_alerts(event, analysis, urgency):
    cfg = CFG
    if cfg.get("slack_webhook"):
        try: _slack(event, analysis, urgency, cfg["slack_webhook"])
        except Exception as e: print(f"Slack: {e}")
    if cfg.get("discord_webhook"):
        try: _discord(event, analysis, urgency, cfg["discord_webhook"])
        except Exception as e: print(f"Discord: {e}")
    if cfg.get("email_to") and cfg.get("email_user"):
        try: _email(event, analysis, urgency)
        except Exception as e: print(f"Email: {e}")

def _slack(event, analysis, urgency, url):
    import requests as req
    colors = {"HIGH":"#e84057","MEDIUM":"#f07030","LOW":"#30c48a","TEST":"#2d7ef7"}
    req.post(url, json={
        "text": f":rotating_light: *[{urgency}] CyberGuard AI — {analysis.get('threat_type','').replace('_',' ').title()}*",
        "attachments":[{"color":colors.get(urgency,"#f07030"),"fields":[
            {"title":"Source IP",     "value":event.get("ip",""),                                       "short":True},
            {"title":"Severity",      "value":f"{analysis.get('severity',0)}/10",                       "short":True},
            {"title":"Confidence",    "value":f"{analysis.get('confidence',0)}%",                       "short":True},
            {"title":"MITRE Tactic",  "value":analysis.get("mitre_tactic","—"),                         "short":True},
            {"title":"Analysis",      "value":analysis.get("reasoning","")[:500],                        "short":False},
            {"title":"Impact",        "value":analysis.get("potential_impact","")[:300],                  "short":False},
        ],"footer":"CyberGuard AI · IPS+IDS","ts":int(time.time())}]
    }, timeout=6)

def _discord(event, analysis, urgency, url):
    import requests as req
    colors = {"HIGH":15220823,"MEDIUM":15758384,"LOW":3196042,"TEST":3014907}
    req.post(url, json={"embeds":[{
        "title": f"🚨 [{urgency}] {analysis.get('threat_type','').replace('_',' ').title()} Detected",
        "color": colors.get(urgency, 15758384),
        "fields":[
            {"name":"Source IP",    "value":event.get("ip",""),                          "inline":True},
            {"name":"Severity",     "value":f"{analysis.get('severity',0)}/10",          "inline":True},
            {"name":"Confidence",   "value":f"{analysis.get('confidence',0)}%",          "inline":True},
            {"name":"MITRE",        "value":f"{analysis.get('mitre_tactic','')} {analysis.get('mitre_technique','')}","inline":True},
            {"name":"Analysis",     "value":analysis.get("reasoning","")[:1000]},
            {"name":"Impact",       "value":analysis.get("potential_impact","")[:500]},
        ],
        "footer":{"text":"CyberGuard AI · Autonomous IPS+IDS"},
        "timestamp":datetime.utcnow().isoformat()+"Z"
    }]}, timeout=6)

def _email(event, analysis, urgency):
    cfg = CFG
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText as MT
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[{urgency}] CyberGuard AI — {analysis.get('threat_type','').replace('_',' ').title()} from {event.get('ip','')}"
    msg["From"]    = cfg.get("email_from") or cfg.get("email_user","")
    msg["To"]      = cfg.get("email_to","")
    body = f"""CyberGuard AI  -  Security Alert

Priority     : {urgency}
Threat       : {analysis.get('threat_type','').replace('_',' ').title()}
Source IP    : {event.get('ip','')}
Severity     : {analysis.get('severity',0)}/10
Confidence   : {analysis.get('confidence',0)}%
MITRE        : {analysis.get('mitre_tactic','')} {analysis.get('mitre_technique','')}
CVE          : {analysis.get('cve_reference','—')}
Kill Chain   : {analysis.get('kill_chain_phase','—')}
Time         : {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

Analysis:
{analysis.get('reasoning','')}

Potential Impact:
{analysis.get('potential_impact','')}

Attack Vector:
{analysis.get('attack_vector','')}

Raw Log:
{event.get('raw_log','')[:500]}

IPS Action:
{chr(10).join(["- " + a for a in analysis.get('actions_taken', [])])}

-- CyberGuard AI  Autonomous IPS+IDS  https://localhost:5000
"""
    msg.attach(MT(body,"plain"))
    with smtplib.SMTP(cfg.get("email_host","smtp.gmail.com"), int(cfg.get("email_port",587))) as s:
        s.ehlo(); s.starttls(); s.ehlo()
        s.login(cfg["email_user"], cfg["email_pass"])
        s.sendmail(msg["From"], msg["To"], msg.as_string())

# ── Live monitor (SSE tail) ───────────────────────────────────────────────────
_mon_stop   = threading.Event()
_mon_q: queue.Queue = queue.Queue()
_mon_thread = None

def _tail(path, q, stop):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(0, 2)
            while not stop.is_set():
                line = f.readline()
                if line: q.put(line.rstrip())
                else:    time.sleep(0.25)
    except Exception as e:
        q.put(f"__ERR__:{e}")

# ── Report generation ─────────────────────────────────────────────────────────
def make_html_report(threats):
    now   = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    pi    = get_platform()
    crit  = sum(1 for t in threats if t.get("severity",0) >= 8)
    blk   = sum(1 for t in threats if t.get("blocked"))
    uniq  = len(set(t["ip_address"] for t in threats))

    rows = "".join(f"""<tr>
      <td><span class="b {('cr' if t.get('severity',0)>=8 else 'hi' if t.get('severity',0)>=6 else 'me' if t.get('severity',0)>=4 else 'lo')}">{('CRITICAL' if t.get('severity',0)>=8 else 'HIGH' if t.get('severity',0)>=6 else 'MEDIUM' if t.get('severity',0)>=4 else 'LOW')}</span></td>
      <td>{t.get('threat_type','').replace('_',' ').title()}</td>
      <td class="mono">{t.get('ip_address','')}</td>
      <td>{t.get('severity',0)}/10</td>
      <td>{t.get('confidence',0)}%</td>
      <td>{t.get('mitre_tactic','—')}</td>
      <td>{t.get('cve_reference','—')}</td>
      <td>{'🛡 Blocked' if t.get('blocked') else '⚠ Alert'}</td>
      <td>{t.get('timestamp','')[:19]}</td>
      <td>{(t.get('reasoning','') or '')[:100]}{'…' if len(t.get('reasoning',''))>100 else ''}</td>
    </tr>""" for t in threats)

    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>CyberGuard AI — Security Report {datetime.now().strftime('%Y-%m-%d')}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;700&family=IBM+Plex+Mono&display=swap');
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Outfit',sans-serif;background:#f4f7fb;color:#1a2235;font-size:13px}}
.wrap{{max-width:1200px;margin:0 auto;padding:36px 28px}}
header{{background:#101520;color:#fff;padding:28px 32px;margin-bottom:28px;border-radius:10px}}
header h1{{font-size:1.6rem;font-weight:700}} header p{{color:#637a94;margin-top:5px;font-size:.82rem}}
.meta{{display:flex;gap:28px;margin-top:18px;flex-wrap:wrap}}
.mi label{{font-size:.6rem;text-transform:uppercase;letter-spacing:.08em;color:#637a94;display:block;margin-bottom:2px}}
.mi span{{font-size:.8rem;color:#a8bacf;font-family:'IBM Plex Mono',monospace}}
.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:24px}}
.stat{{background:#fff;border:1px solid #e2e8f0;padding:18px;border-radius:8px}}
.sv{{font-size:1.9rem;font-weight:700;letter-spacing:-.04em;line-height:1}}
.sl{{font-size:.7rem;color:#637a94;margin-top:3px}}
.stat.r .sv{{color:#e84057}}.stat.o .sv{{color:#f07030}}.stat.b .sv{{color:#2d7ef7}}.stat.g .sv{{color:#30c48a}}
section{{background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:22px;margin-bottom:22px}}
h2{{font-size:.95rem;font-weight:700;margin-bottom:14px;padding-bottom:8px;border-bottom:2px solid #e2e8f0}}
table{{width:100%;border-collapse:collapse;font-size:.74rem}}
th{{padding:8px 10px;text-align:left;font-size:.6rem;letter-spacing:.08em;text-transform:uppercase;color:#637a94;border-bottom:2px solid #e2e8f0;background:#f8fafc;white-space:nowrap}}
td{{padding:9px 10px;border-bottom:1px solid #f0f4f8;vertical-align:top}}
tr:last-child td{{border-bottom:none}}
.b{{display:inline-block;padding:2px 7px;border-radius:3px;font-size:.6rem;font-weight:700}}
.b.cr{{background:#fde8ec;color:#e84057}}.b.hi{{background:#fef0e8;color:#f07030}}
.b.me{{background:#fef8e8;color:#d4960a}}.b.lo{{background:#e8faf4;color:#1d9262}}
.mono{{font-family:'IBM Plex Mono',monospace;font-size:.7rem}}
footer{{text-align:center;padding:20px;color:#637a94;font-size:.72rem;margin-top:24px;border-top:1px solid #e2e8f0}}
@media print{{body{{background:#fff}}.wrap{{padding:12px}}}}
</style></head><body><div class="wrap">
<header>
  <h1>🛡 CyberGuard AI — Security Operations Report</h1>
  <p>AI-Powered IPS + IDS — Autonomous Threat Detection &amp; Response</p>
  <div class="meta">
    <div class="mi"><label>Generated</label><span>{now}</span></div>
    <div class="mi"><label>Platform</label><span>{pi.get('os_detail','')}</span></div>
    <div class="mi"><label>Hostname</label><span>{pi.get('hostname','')}</span></div>
    <div class="mi"><label>Total Events</label><span>{len(threats)}</span></div>
  </div>
</header>
<div class="stats">
  <div class="stat r"><div class="sv">{len(threats)}</div><div class="sl">Total Threats</div></div>
  <div class="stat o"><div class="sv">{crit}</div><div class="sl">Critical Severity</div></div>
  <div class="stat b"><div class="sv">{blk}</div><div class="sl">IPs Blocked (IPS)</div></div>
  <div class="stat g"><div class="sv">{uniq}</div><div class="sl">Unique Source IPs</div></div>
</div>
<section>
  <h2>Threat Intelligence Feed</h2>
  <table><thead><tr>
    <th>Severity</th><th>Threat Type</th><th>Source IP</th><th>Score</th>
    <th>Confidence</th><th>MITRE Tactic</th><th>CVE</th><th>IPS Action</th>
    <th>Timestamp</th><th>AI Summary</th>
  </tr></thead><tbody>{rows}</tbody></table>
</section>
<footer>CyberGuard AI · AI-Powered IPS+IDS · {now}</footer>
</div></body></html>"""

def make_pdf_report(threats):
    try:
        from fpdf import FPDF
        pi  = get_platform()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        pdf = FPDF()
        pdf.set_auto_page_break(True, 15)
        pdf.add_page()

        # Header bar
        pdf.set_fill_color(16,21,32)
        pdf.rect(0,0,210,36,"F")
        pdf.set_text_color(240,244,248)
        pdf.set_font("Helvetica","B",16)
        pdf.set_xy(14,8)
        pdf.cell(0,8,"CyberGuard AI  -  Security Report",ln=True)
        pdf.set_font("Helvetica","",8)
        pdf.set_xy(14,20)
        pdf.set_text_color(99,122,148)
        pdf.cell(0,5,f"AI-Powered IPS+IDS  |  Generated: {now}  |  {pi.get('os_detail','')}  |  {pi.get('hostname','')}")
        pdf.set_text_color(30,30,30)

        # Stats row
        crit = sum(1 for t in threats if t.get("severity",0)>=8)
        blk  = sum(1 for t in threats if t.get("blocked"))
        uniq = len(set(t["ip_address"] for t in threats))
        stats=[("Total Threats",len(threats),"e84057"),("Critical",crit,"f07030"),
               ("IPs Blocked",blk,"2d7ef7"),("Unique IPs",uniq,"30c48a")]
        x=14
        for label,val,_ in stats:
            pdf.set_fill_color(244,247,251)
            pdf.rect(x,42,43,20,"F")
            pdf.set_font("Helvetica","B",15)
            pdf.set_text_color(30,30,30)
            pdf.set_xy(x,44); pdf.cell(43,8,str(val),align="C")
            pdf.set_font("Helvetica","",7)
            pdf.set_text_color(99,122,148)
            pdf.set_xy(x,53); pdf.cell(43,4,label,align="C")
            x+=47

        pdf.set_xy(14,70)
        pdf.set_font("Helvetica","B",10)
        pdf.set_text_color(30,30,30)
        pdf.cell(0,6,"Threat Intelligence Feed",ln=True)

        # Table header
        pdf.set_fill_color(26,34,53); pdf.set_text_color(240,244,248)
        pdf.set_font("Helvetica","B",6.5)
        hdrs=[("Severity",18),("Type",30),("IP",28),("Score",12),
              ("Conf",12),("MITRE",30),("Action",18),("Timestamp",28),("Summary",32)]
        for h,w in hdrs:
            pdf.cell(w,6,h,fill=True)
        pdf.ln()

        pdf.set_text_color(30,30,30)
        fill=False
        colors={"CRITICAL":(232,64,87),"HIGH":(240,112,48),"MEDIUM":(232,176,48),"LOW":(48,196,138)}
        for t in threats:
            sev=t.get("severity",0)
            lbl="CRITICAL" if sev>=8 else "HIGH" if sev>=6 else "MEDIUM" if sev>=4 else "LOW"
            c=colors[lbl]
            pdf.set_fill_color(248,249,252) if fill else pdf.set_fill_color(255,255,255)
            fill=not fill
            pdf.set_font("Helvetica","B",6.5); pdf.set_text_color(*c)
            pdf.cell(18,5.5,lbl,fill=True)
            pdf.set_font("Helvetica","",6.5); pdf.set_text_color(30,30,30)
            pdf.cell(30,5.5,t.get("threat_type","").replace("_"," ").title()[:18],fill=True)
            pdf.cell(28,5.5,t.get("ip_address",""),fill=True)
            pdf.cell(12,5.5,f"{sev}/10",fill=True)
            pdf.cell(12,5.5,f"{t.get('confidence',0)}%",fill=True)
            pdf.cell(30,5.5,(t.get("mitre_tactic","—") or "—")[:18],fill=True)
            pdf.cell(18,5.5,"Blocked" if t.get("blocked") else "Alert",fill=True)
            pdf.cell(28,5.5,(t.get("timestamp","") or "")[:19],fill=True)
            sm=(t.get("reasoning","") or "")[:30]+("…" if len(t.get("reasoning","")or"")>30 else "")
            pdf.cell(32,5.5,sm,fill=True)
            pdf.ln()

        pdf.set_xy(14,pdf.get_y()+8)
        pdf.set_font("Helvetica","I",7)
        pdf.set_text_color(150,150,150)
        pdf.cell(0,4,"CyberGuard AI  ·  AI-Powered IPS+IDS  ·  Autonomous Security Operations",align="C")
        return pdf.output()
    except ImportError:
        return None

# ══════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════
# AUTH ROUTES
# ══════════════════════════════════════════════════════════════

@app.route("/api/auth/status")
def auth_status():
    return jsonify({
        "needs_setup":    auth_needs_setup(),
        "authenticated":  bool(session.get("authenticated")),
        "username":       session.get("username", ""),
    })

@app.route("/api/auth/setup", methods=["POST"])
def auth_setup():
    if not auth_needs_setup():
        return jsonify({"error": "Admin account already exists"}), 400
    data = request.get_json(force=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password", "")
    if not username or len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    auth_save(username, password)
    session["authenticated"] = True
    session["username"] = username
    session.permanent = True
    print(f"  ✓ Admin account created: {username}")
    return jsonify({"status": "created", "username": username})

@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    if auth_needs_setup():
        return jsonify({"error": "setup_required"}), 400
    ip = request.remote_addr or "unknown"
    allowed, wait = _login_allowed(ip)
    if not allowed:
        return jsonify({"error": f"Too many attempts. Try again in {wait}s"}), 429

    data     = request.get_json(force=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password", "")

    stored = auth_get()
    if (username == stored.get("username") and
            _verify_password(password, stored.get("password_hash", ""))):
        # Clear rate limit on success
        with _LOGIN_LOCK:
            _LOGIN_ATTEMPTS[ip] = []
        session.clear()
        session["authenticated"] = True
        session["username"]      = username
        session.permanent        = True
        return jsonify({"status": "ok", "username": username})

    return jsonify({"error": "Invalid username or password"}), 401

@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    username = session.get("username", "")
    session.clear()
    return jsonify({"status": "logged_out", "username": username})

@app.route("/api/auth/change-password", methods=["POST"])
def auth_change_password():
    data         = request.get_json(force=True) or {}
    current      = data.get("current_password", "")
    new_password = data.get("new_password", "")
    stored       = auth_get()

    if not _verify_password(current, stored.get("password_hash", "")):
        return jsonify({"error": "Current password is incorrect"}), 401
    if len(new_password) < 8:
        return jsonify({"error": "New password must be at least 8 characters"}), 400

    auth_save(stored["username"], new_password)
    return jsonify({"status": "changed"})

# ══════════════════════════════════════════════════════════════
@app.route("/")
def index():
    return send_from_directory("static","index.html")

@app.route("/api/health")
def health():
    cfg = load_config(); CFG.update(cfg)
    pi  = get_platform()
    has_groq  = bool(cfg.get("groq_api_key") and cfg.get("groq_api_key") != "your_groq_api_key_here")
    return jsonify({
        "status":          "healthy",
        "platform":        pi,
        "groq_api":        "configured" if has_groq else "missing",
        "slack_webhook":   "configured" if cfg.get("slack_webhook") else "not configured",
        "discord_webhook": "configured" if cfg.get("discord_webhook") else "not configured",
        "email":           "configured" if (cfg.get("email_to") and cfg.get("email_user")) else "not configured",
        "ips_mode":        cfg.get("ips_mode", True),
        "blocked_count":   len(BLOCKED_IPS),
        "monitor_path":    cfg.get("monitor_log_path",""),
        "server_time":     datetime.now().isoformat(),
    })

@app.route("/api/config", methods=["GET"])
def get_config_route():
    cfg = load_config()
    safe = {}
    for k, v in cfg.items():
        if k == "groq_api_key":
            # Return first 8 chars so frontend can show masked placeholder
            safe[k] = v[:8] + "…" if (v and v != "your_groq_api_key_here" and len(v) > 8) else v
        elif "pass" in k.lower():
            safe[k] = "***" if v else ""
        else:
            safe[k] = v
    return jsonify(safe)

@app.route("/api/config", methods=["POST"])
def post_config():
    global CFG
    data = request.get_json(force=True)
    if not data:
        return jsonify({"status": "error", "message": "No data"}), 400
    cur = load_config()
    for k, v in data.items():
        if v != "***" and v is not None:
            cur[k] = v
    save_config(cur)
    CFG = cur
    # Reload Groq client if key was updated
    has_groq = bool(cur.get("groq_api_key") and cur.get("groq_api_key") != "your_groq_api_key_here")
    return jsonify({"status": "saved", "groq_active": has_groq})

@app.route("/api/test-alert", methods=["POST"])
def test_alert():
    data = request.get_json(force=True)
    ch   = data.get("channel")
    ev   = {"ip":"1.2.3.4","raw_log":"TEST","reasons":["Test alert"]}
    an   = {"threat_type":"test","severity":5,"confidence":100,
            "reasoning":"CyberGuard AI test alert — configuration verified.",
            "potential_impact":"N/A","mitre_tactic":"—","mitre_technique":"—",
            "cve_reference":"","kill_chain_phase":"—","actions_taken":[]}
    try:
        if ch == "slack":
            url = data.get("url") or CFG.get("slack_webhook","")
            if not url: return jsonify({"ok":False,"error":"No webhook URL"}),400
            _slack(ev,an,"TEST",url)
        elif ch == "discord":
            url = data.get("url") or CFG.get("discord_webhook","")
            if not url: return jsonify({"ok":False,"error":"No webhook URL"}),400
            _discord(ev,an,"TEST",url)
        elif ch == "email":
            _email(ev,an,"TEST")
        else:
            return jsonify({"ok":False,"error":"Unknown channel"}),400
        return jsonify({"ok":True})
    except Exception as e:
        return jsonify({"ok":False,"error":str(e)}),500

@app.route("/api/analyze-log", methods=["POST"])
def analyze_log():
    if "file" not in request.files:
        return jsonify({"error":"No file"}),400
    content = request.files["file"].read().decode("utf-8",errors="ignore")
    events  = parse_content(content)
    limit   = int(CFG.get("max_analyze_per_upload",50))
    results = []
    for ev in events[:limit]:
        an  = analyze(ev)
        rec = decide(ev,an,"upload")
        results.append(rec)
    return jsonify({"total_events":len(events),"analyzed":len(results),"decisions":results})

@app.route("/api/monitor/start", methods=["POST"])
def monitor_start():
    global _mon_thread, _mon_stop, _mon_q
    data = request.get_json(force=True)
    path = (data.get("path","") or CFG.get("monitor_log_path","")).strip()
    if not path: return jsonify({"error":"No log path"}),400
    if not os.path.exists(path): return jsonify({"error":f"Not found: {path}"}),404
    _mon_stop.set(); time.sleep(0.4)
    _mon_stop = threading.Event()
    _mon_q    = queue.Queue()
    _mon_thread = threading.Thread(target=_tail,args=(path,_mon_q,_mon_stop),daemon=True)
    _mon_thread.start()
    return jsonify({"status":"monitoring","path":path})

@app.route("/api/monitor/stop", methods=["POST"])
def monitor_stop():
    _mon_stop.set()
    return jsonify({"status":"stopped"})

@app.route("/api/stream")
def stream():
    def generate():
        yield f"data: {json.dumps({'type':'connected'})}\n\n"
        while True:
            try:
                line = _mon_q.get(timeout=1.0)
                if line.startswith("__ERR__:"):
                    yield f"data: {json.dumps({'type':'error','message':line[8:]})}\n\n"; break
                # DDoS check per live IP
                m = re.match(r'(\d+\.\d+\.\d+\.\d+)',line)
                live_ip = m.group(1) if m else ""
                ddos_ev = record_request(live_ip) if live_ip else None
                if ddos_ev:
                    an  = analyze(ddos_ev)
                    rec = decide(ddos_ev,an,"live")
                    yield f"data: {json.dumps({'type':'threat','line':line,'record':rec})}\n\n"
                    continue
                ev = parse_line(line)
                if ev:
                    an  = analyze(ev)
                    rec = decide(ev,an,"live")
                    yield f"data: {json.dumps({'type':'threat','line':line,'record':rec})}\n\n"
                else:
                    yield f"data: {json.dumps({'type':'line','line':line})}\n\n"
            except queue.Empty:
                yield f"data: {json.dumps({'type':'heartbeat'})}\n\n"
    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@app.route("/api/threats")
def threats_route():
    return jsonify(db_all())

@app.route("/api/threats/blocked")
def blocked_threats():
    return jsonify([t for t in db_all() if t.get("blocked")])

@app.route("/api/threats/clear", methods=["POST"])
def clear_threats():
    db_clear(); return jsonify({"status":"cleared"})

@app.route("/api/blocked-ips")
def blocked_ips():
    return jsonify(list(BLOCKED_IPS.values()))

@app.route("/api/blocked-ips/unblock", methods=["POST"])
def unblock_ip():
    ip = request.get_json(force=True).get("ip","")
    with BLOCK_LOCK:
        BLOCKED_IPS.pop(ip, None)
    return jsonify({"status":"unblocked","ip":ip})

@app.route("/api/stats")
def stats():
    all_t = db_all()
    return jsonify({
        "total_threats":   len(all_t),
        "total_decisions": len(all_t),
        "blocked_ips":     sum(1 for t in all_t if t.get("blocked")),
        "live_blocked":    len(BLOCKED_IPS),
        "alerts_sent":     sum(1 for t in all_t if t.get("alert_sent")),
        "high_severity":   sum(1 for t in all_t if t.get("severity",0) >= 7),
        "critical":        sum(1 for t in all_t if t.get("severity",0) >= 8),
        "unique_ips":      len(set(t["ip_address"] for t in all_t)),
        "ddos_detected":   sum(1 for t in all_t if t.get("threat_type") == "ddos"),
    })

@app.route("/api/report/json")
def report_json():
    pi   = get_platform()
    data = {"report_generated":datetime.now().isoformat(),"platform":pi,
            "blocked_ips":list(BLOCKED_IPS.values()),"threats":db_all()}
    buf = io.BytesIO(json.dumps(data,indent=2).encode()); buf.seek(0)
    return send_file(buf,mimetype="application/json",as_attachment=True,
                     download_name=f"cyberguard-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json")

@app.route("/api/report/html")
def report_html():
    buf = io.BytesIO(make_html_report(db_all()).encode()); buf.seek(0)
    return send_file(buf,mimetype="text/html",as_attachment=True,
                     download_name=f"cyberguard-{datetime.now().strftime('%Y%m%d-%H%M%S')}.html")

@app.route("/api/report/pdf")
def report_pdf():
    pdf = make_pdf_report(db_all())
    if pdf is None:
        buf = io.BytesIO(make_html_report(db_all()).encode()); buf.seek(0)
        return send_file(buf,mimetype="text/html",as_attachment=True,
                         download_name=f"cyberguard-{datetime.now().strftime('%Y%m%d-%H%M%S')}.html")
    buf = io.BytesIO(pdf); buf.seek(0)
    return send_file(buf,mimetype="application/pdf",as_attachment=True,
                     download_name=f"cyberguard-{datetime.now().strftime('%Y%m%d-%H%M%S')}.pdf")

if __name__ == "__main__":
    pi  = get_platform()
    cfg = load_config()
    print("\n" + "═"*56)
    print("  🛡  CyberGuard AI  —  Autonomous IPS + IDS")
    print("═"*56)
    print(f"  OS       : {pi['os_detail']}")
    print(f"  Hostname : {pi['hostname']}")
    print(f"  Arch     : {pi['machine']} · {pi['architecture']}")
    print(f"  Python   : {pi['python_version']}")
    print(f"  Groq AI  : {'✓ configured' if (cfg.get('groq_api_key') and cfg.get('groq_api_key') != 'your_groq_api_key_here') else '✗ heuristic mode'}")
    print(f"  Auth     : {'✓ admin account exists — login required' if not auth_needs_setup() else '⚠ first run — setup required at http://localhost:5000'}")
    print(f"  Slack    : {'✓' if cfg.get('slack_webhook') else '—'}")
    print(f"  Discord  : {'✓' if cfg.get('discord_webhook') else '—'}")
    print(f"  Email    : {'✓' if cfg.get('email_to') else '—'}")
    print(f"\n  Dashboard → http://localhost:5000")
    print("═"*56 + "\n")
    app.run(host="0.0.0.0",port=5000,debug=False,threaded=True)
