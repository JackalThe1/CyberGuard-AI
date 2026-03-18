# 🔒 CyberGuard AI — Cross-Platform MVP

**Autonomous cybersecurity operations platform with AI-powered threat detection.**

Works on **Windows**, **macOS**, and **Linux** — one command, any OS.

---

## ⚡ Quick Start (5 minutes)

### Step 1 — Prerequisites

Python 3.9+ (https://www.python.org/downloads/)

### Step 2 — Get Your Groq API Key (FREE)

1. Go to https://console.groq.com
2. Sign up / log in
3. Create an API key
4. Copy it

> **No Groq key?** The app still runs using heuristic analysis — just leave `GROQ_API_KEY=` blank in `.env`.

### Step 3 — Configure

**Windows (CMD / PowerShell):**
```cmd
cd cyberguard-ai-mvp
copy .env.example .env
notepad .env
```

**macOS / Linux:**
```bash
cd cyberguard-ai-mvp
cp .env.example .env
nano .env
```

Edit `.env`:
```
GROQ_API_KEY=gsk_your_key_here
SLACK_WEBHOOK_URL=          # optional
DISCORD_WEBHOOK_URL=        # optional
```

### Step 4 — Run

```bash
# Windows
python start.py

# macOS / Linux
python3 start.py
```

The launcher will:
- ✅ Check Python version
- ✅ Install missing packages automatically
- ✅ Verify config
- ✅ Start the server
- ✅ Open your browser to http://localhost:5000

---

## 🎯 Demo Flow

1. Open **http://localhost:5000**
2. Click **"Browse"** and select `sample_logs/apache_access.log`
3. Click **"⚡ Analyze Threats"**
4. Watch the AI autonomously:
   - Detect brute-force, SQLi, XSS, directory traversal, reconnaissance
   - Classify severity (1–10)
   - Generate firewall commands for every OS
   - Send Slack/Discord alerts (if configured)

---

## 🏗️ Architecture

```
Browser (any OS)
    │ REST API
    ▼
Python Flask Backend
    ├── Log Parser (regex-based)
    ├── AI Analyzer (Groq / Llama 3.1 70B)
    ├── Decision Engine (block / alert / monitor)
    └── Alert System (Slack / Discord webhooks)
    │
    ▼
SQLite Database (portable, zero config)
```

---

## 📁 File Structure

```
cyberguard-ai-mvp/
├── start.py                # Universal launcher
├── app.py                  # Flask backend
├── static/
│   └── index.html          # Dashboard (no build step needed)
├── requirements.txt        # Pure Python dependencies
├── .env.example            # Config template
├── README.md               # This file
├── sample_logs/
│   └── apache_access.log   # Demo log data
└── data/
    └── threats.db          # Auto-created SQLite DB
```

---

## 🔍 Detected Threat Types

| Type | Detection Method |
|---|---|
| Brute Force | 5+ failed auth attempts from same IP |
| SQL Injection | Pattern match on UNION/SELECT/DROP/-- etc. |
| Directory Traversal | `../` and `%2F..` path patterns |
| XSS | `<script>`, `onerror=`, `alert()` in paths |
| Malicious Bot | sqlmap, nikto, masscan, nmap user agents |
| Reconnaissance | Probing for .env, wp-config, phpmyadmin |

---

## 🛡️ Autonomous Decisions

| Severity | Action |
|---|---|
| 7–10 (HIGH) | Generate firewall blocks + send HIGH alert |
| 4–6 (MEDIUM) | Send MEDIUM alert |
| 1–3 (LOW) | Add to monitoring watchlist |

Firewall commands are generated for **all platforms simultaneously** (UFW, iptables, macOS pf, Windows netsh, PowerShell).

---

## 🔧 Troubleshooting

**"python not found"**
→ Try `python3` or ensure Python is in your PATH

**"Module not found"**
→ Run: `python -m pip install -r requirements.txt`

**"Port 5000 in use"**
→ Edit `app.py`, change `port=5000` to `port=5001`

**AI not working**
→ Check your `GROQ_API_KEY` in `.env` — app works without it (heuristic mode)

---

## 🏆 What Makes This Cross-Platform

- ✅ Pure Python — no OS binaries
- ✅ SQLite — built into Python, zero setup
- ✅ Flask — cross-platform HTTP server
- ✅ pathlib — universal path handling
- ✅ Cloud AI (Groq) — no local ML models
- ✅ Browser dashboard — any modern browser
- ✅ No Docker, no compilation, no admin rights needed

---

## 📦 Tech Stack

- **Python 3.9+** — core runtime
- **Flask 3.0** — web server
- **Groq API** — Llama 3.1 70B inference (cloud)
- **SQLite** — embedded database
- **Vanilla JS + CSS** — zero-build frontend

---

MIT License — Open Source
