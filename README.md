```markdown
# ⬢ NEUTRA · ARCHIVE // SECTOR 7G

> 🔍 One file. Every tool you need to dig through public data.
> No npm. No pip. No docker. Just Python and a browser.

```
  ███╗   ██╗███████╗██╗   ██╗████████╗██████╗  █████╗
  ████╗  ██║██╔════╝██║   ██║╚══██╔══╝██╔══██╗██╔══██╗
  ██╔██╗ ██║█████╗  ██║   ██║   ██║   ██████╔╝███████║
  ██║╚██╗██║██╔══╝  ██║   ██║   ██║   ██╔══██╗██╔══██║
  ██║ ╚████║███████╗╚██████╔╝   ██║   ██║  ██║██║  ██║
  ╚═╝  ╚═══╝╚══════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
```

---

## ⚡ What is this

NEUTRA is a single Python file that turns into a full OSINT dashboard when you run it. It gives you 70+ tools in one screen. You feed it a target. It fires every relevant module at once, ranks the results, and draws you a graph of everything it found.

You get one HTML file for the UI and one Python file for the brain. That is it.

---

## 🎯 What you can throw at it

| Symbol | Type | Example |
|--------|------|---------|
| 📧 | Email | `someone@example.com` |
| 🌐 | Domain | `example.com` |
| 🔗 | URL | `https://example.com/path` |
| 📡 | IP address | `8.8.8.8` |
| 🔢 | ASN | `AS15169` |
| 📞 | Phone | `+14155552671` |
| 👤 | Username | `@someuser` |
| 🧑 | Full name | `John Smith` |
| 🐛 | CVE | `CVE-2024-1234` |
| 🔐 | Hash | `5d41402abc4b2a76b9719d911017c592` |
| 💰 | Wallet | `0x...` or `bc1...` |
| 📍 | Coords | `40.7128,-74.0060` |

Type it in the box. Hit scan. Done.

---

## 🧠 How it works

```
   YOU  ──►  type target
           │
           ▼
       ┌─────────┐
       │ DETECT  │  ── what kind of thing is this?
       └────┬────┘
            │
            ▼
       ┌─────────┐
       │ DISPATCH│  ── pick every module that fits
       └────┬────┘
            │
            ▼
       ┌─────────┐
       │ RUN ALL │  ── 8 at a time, in parallel
       └────┬────┘
            │
            ▼
       ┌─────────┐
       │ CORRELATE│ ── pull out emails, IPs, names, phones
       └────┬────┘
            │
            ▼
       ┌─────────┐
       │  GRAPH  │  ── draw connections, rank confidence
       └─────────┘
```

Every result gets a **confidence score**. Every finding becomes a **pivot** you can click to dig deeper. The timeline shows what happened in what order.

---

## 🗂️ Categories

### 🌐 Domain
Dig into any website. DNS records, TLS certificates, subdomains, who registered it, where it is hosted, what tech it runs on, whether its email is spoofable.

Modules: `dns` `certs` `crt_history` `subdomains` `rdap` `hosting` `wayback` `wayback_cdx` `archive_today` `emailsec` `headers` `robots` `tech` `mx_provider`

### 📡 Network
Everything about an IP. Where it lives, who owns it, is it a VPN or proxy, does it have open ports, is it malicious.

Modules: `ipgeo` `iprdap` `asn` `ip_abuse` `reverse_dns` `shodan_idb` `greynoise`

### 📧 Email
Is this address real. Has it leaked. What sites use it. Any infostealer malware grabbed it. Any fraud signals.

Modules: `email_breach` `people_email` `gravatar` `email_disposable` `email_mx` `emailrep` `hunter_io` `ipqs_email` `breach_directory` `hudson_rock_email`

### 👤 Username
Hunt a handle across dozens of platforms. Global sites, regional sites (VK, Weibo, Bilibili), and dev sites (GitLab, NPM, PyPI).

Modules: `social_username` `username_regional` `username_dev` `username_archives` `footprint`

### 📞 Phone
Where does this number live. What carrier. Is it a real line or a burner. Any fraud flags.

Modules: `phone` `phone_carrier` `veriphone` `ipqs_phone`

### 🧑 People ⟵ NEW
Public-records style digging. Sanctions lists, court records, SEC filings, campaign donations, corporate officers, name demographics.

Modules:
- `genderize` — guess gender from first name
- `agify` — guess age from first name
- `nationalize` — guess nationality from first name
- `wikidata_person` — find in Wikidata
- `wikipedia_person` — biography summary
- `open_sanctions` — sanctions and PEP screening
- `ofac_sdn` — US Treasury watchlist
- `sec_edgar_person` — insider trades and officers
- `fec_search` — political donations
- `court_listener` — US court cases
- `open_corporates` — company officers
- `pipl` — deep people search (needs key)
- `social_analyzer` — username with confidence
- `whatsmyname` — community platform list

### 🐛 Threat
CVE details, IOC lookups, malware samples, url scans.

Modules: `cve` `hashid` `urlscan_search` `otx_lookup` `urlhaus` `threatfox` `malwarebazaar`

### 💰 Crypto
Wallet balances and activity.

Modules: `crypto_eth` `crypto_btc` `sanctions`

### 🔍 Search
Wikipedia, GitHub, dork builders, reverse geocode.

Modules: `wikipedia` `github_search` `github_code` `dork` `reverse`

---

## 💻 Install on Windows (PowerShell)

This is the easy path. Copy and paste.

### 📥 Option 1 — One shot installer

Open **PowerShell as Administrator** and paste this:

```powershell
# Make a folder for it
New-Item -ItemType Directory -Force -Path "$HOME\neutra" | Out-Null
Set-Location "$HOME\neutra"

# Grab the files (replace with your real URLs when hosted)
Invoke-WebRequest -Uri "https://your-host/neutra.py" -OutFile "neutra.py"
Invoke-WebRequest -Uri "https://your-host/UI.html"   -OutFile "UI.html"

# Check Python exists
$py = (Get-Command python -ErrorAction SilentlyContinue)
if (-not $py) {
    Write-Host "Python not found. Installing via winget..." -ForegroundColor Yellow
    winget install -e --id Python.Python.3.12 --accept-source-agreements --accept-package-agreements
    # Refresh PATH in this session
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
}

# Run it
python .\neutra.py
```

### 📥 Option 2 — Step by step

**1. Install Python** (if you do not have it)

```powershell
winget install -e --id Python.Python.3.12
```

Or grab it from https://www.python.org/downloads/ and tick **"Add Python to PATH"** during install.

**2. Make a folder**

```powershell
mkdir $HOME\neutra
cd $HOME\neutra
```

**3. Drop the two files in**

Put `neutra.py` and `UI.html` in that folder. Same folder. Side by side.

**4. Run it**

```powershell
python .\neutra.py
```

Browser opens by itself to `http://127.0.0.1:8765`.

### 🔑 Option 3 — With API keys

```powershell
$env:GITHUB_TOKEN   = "ghp_yourtoken"
$env:IPQS_KEY       = "yourkey"
$env:VERIPHONE_KEY  = "yourkey"
$env:COURTLISTENER_KEY = "yourkey"
$env:HUNTER_KEY     = "yourkey"
$env:FEC_API_KEY    = "yourkey"
$env:EMAILREP_KEY   = "yourkey"
$env:NEUTRA_AUTH    = "admin:secretpass"

python .\neutra.py
```

### 🧷 Option 4 — Make a shortcut

Create `start-neutra.bat` next to the files:

```bat
@echo off
cd /d "%~dp0"
python neutra.py
pause
```

Double click it. Done.

### 🌐 Option 5 — Run without opening a browser

```powershell
python .\neutra.py --no-browser
```

Then open `http://127.0.0.1:8765` yourself.

### 🛑 Firewall prompt

First run, Windows might ask. Click **Allow** for private networks. If you do not want it on the network, run with:

```powershell
$env:NEUTRA_HOST = "127.0.0.1"
python .\neutra.py
```

### 🧹 Uninstall

```powershell
Remove-Item -Recurse -Force $HOME\neutra
```

That is everything. No registry junk. No services. Just a folder.

---

## 🐧 Install on Linux / macOS

```bash
git clone <your-repo> neutra && cd neutra
python3 neutra.py
```

Or:

```bash
mkdir -p ~/neutra && cd ~/neutra
curl -O https://your-host/neutra.py
curl -O https://your-host/UI.html
python3 neutra.py
```

---

## 🎛️ Environment variables

All optional. Set the ones you have.

```bash
# Server
export PORT=8765
export NEUTRA_HOST=0.0.0.0
export NEUTRA_AUTH="admin:secretpass"

# API keys (unlock premium tiers)
export GITHUB_TOKEN=ghp_xxxxx
export NUMVERIFY_KEY=xxxxx
export VERIPHONE_KEY=xxxxx
export IPQS_KEY=xxxxx
export COURTLISTENER_KEY=xxxxx
export HUNTER_KEY=xxxxx
export PIPL_KEY=xxxxx
export EMAILREP_KEY=xxxxx
export FEC_API_KEY=xxxxx
export SHODAN_KEY=xxxxx
export GREYNOISE_KEY=xxxxx
export VT_KEY=xxxxx
export OTX_KEY=xxxxx
```

Windows PowerShell syntax for all of them is in the install section above.

Run without any keys. Most modules still work.

---

## ⌨️ Keyboard shortcuts

| Key | What it does |
|-----|--------------|
| `Ctrl + K` | Open command palette |
| `/` | Jump to search box |
| `Enter` | Run scan or AI |
| `Esc` | Close palette |

---

## 🖥️ The UI

Monochrome. Robotic. Built for focus.

- Black background, white text, scanlines
- Synthesized sound effects (no audio files)
- Live confidence bars
- Interactive force graph (drag the nodes)
- Command palette (Ctrl + K)
- Timeline view of every action
- Cases, bookmarks, history all saved to disk

Run an AI investigation and you get:

- 📝 A summary paragraph
- 🏷️ Every entity it found (emails, IPs, names, phones, URLs)
- 📊 Confidence ranking of each module
- ⏱️ Full timeline
- 🎯 Suggested pivots to keep digging
- 🕸️ Relationship graph

---

## 📁 Where data goes

Everything lives in `neutra_data/` next to the script.

```
neutra_data/
├── cases.json       ← saved investigations
├── history.json     ← every scan you ran
└── bookmarks.json   ← your saved stuff
```

Plain JSON. Read it, edit it, delete it.

On Windows that means:

```powershell
C:\Users\<you>\neutra\neutra_data\
```

---

## 🔒 Auth mode

Want to expose this on a network? Set a password.

**Linux / macOS:**
```bash
NEUTRA_AUTH="youruser:yourpass" python3 neutra.py
```

**Windows PowerShell:**
```powershell
$env:NEUTRA_AUTH = "youruser:yourpass"
python .\neutra.py
```

Every request needs HTTP Basic auth. Health check stays open.

---

## 🛡️ Legal and ethics

Every module here hits **public data only**. No scraping private databases. No credential stuffing. No bypassing anything.

What this means for you:

- ✅ Public DNS, WHOIS, cert transparency — fine
- ✅ Sanctions and court records — fine, they are public
- ✅ Have I Been Pwned style breach checks — fine, that is the whole point
- ✅ Username checks on public profiles — fine
- ❌ Do not use this to stalk, harass, or dox anyone
- ❌ Do not use this for unauthorized access
- ❌ Do not violate platform terms of service

Check your local laws. GDPR, CCPA, and similar rules apply. When in doubt, ask yourself: would a journalist do this. If yes, you are fine.

---

## 📦 Requirements

- Python 3.8 or newer
- Standard library only (no pip install needed)
- A modern browser

That is it. No node_modules. No virtual env. No build step.

---

## 🎨 Module breakdown

Want to see everything at once? Open `/api/catalog` in your browser while the server runs.

```
GET http://127.0.0.1:8765/api/catalog
```

You get back a JSON of every module, its category, its weight, and what inputs it accepts.

---

## 🧪 API endpoints

The whole thing is a REST API. Hack on it.

| Method | Path | What it does |
|--------|------|--------------|
| `GET` | `/` | The UI |
| `GET` | `/healthz` | Is it alive |
| `GET` | `/api/detect?q=...` | What type is this input |
| `GET` | `/api/catalog` | List every module |
| `GET` | `/api/run?m=...&q=...` | Run one module |
| `GET` | `/api/ai/start?q=...` | Start full investigation |
| `GET` | `/api/ai/poll?job=...` | Check progress |
| `GET` | `/api/ai/report?job=...&fmt=md` | Download report |
| `GET` | `/api/cases` | List saved cases |
| `GET` | `/api/history` | Scan history |
| `GET` | `/api/bookmarks` | Saved bookmarks |

---

## 🎬 Quick examples

**Hunt a username:**
```
type: @someuser
click: AI
wait: ~15 seconds
result: every profile, every breach, every archive hit
```

**Dig into a domain:**
```
type: example.com
click: SCAN
result: DNS, certs, subdomains, hosting, tech stack, email security
```

**Check an email for leaks:**
```
type: someone@example.com
click: SCAN
result: breach hits, reputation, infostealer data, linked accounts
```

**Screen a name:**
```
type: John Smith
click: AI
result: sanctions, court records, SEC filings, donations, corporate roles
```

---

## 🛠️ Adding your own module

Drop a function in the file. Register it. Restart. Done.

```python
def p_my_tool(q):
    j = get("https://api.example.com/lookup?q=" + up.quote(q))
    return {"rows": [("Field", j.get("value", "?"))]}

register("my_tool", "My Tool", "What it does", "Search", ["domain"], p_my_tool, 1.0)
```

That is the whole pattern.

---

## 🧯 Troubleshooting

**Browser does not open**
Run with `--no-browser` and go to the URL yourself.

**Port already in use**
Linux / macOS: `PORT=9999 python3 neutra.py`
Windows: `$env:PORT = "9999"; python .\neutra.py`

**`python` is not recognized (Windows)**
Reinstall Python and tick **"Add Python to PATH"**, or use `py` instead:

```powershell
py .\neutra.py
```

**PowerShell blocks the script**
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

**Module returns empty**
Many APIs need keys. Check the environment section.

**UI looks broken**
Make sure `UI.html` sits next to `neutra.py`.

**Rate limited**
Some free APIs cap you. Wait a minute.

---

## 🏴 Final notes

Built for researchers, journalists, and security folks who want one tool that does a lot without installing anything.

If you find a bug, patch it. If you find a new API, add a module. If you break something, `git checkout` fixes it.

Everything here hits public sources. You are responsible for how you use it.

```
  A R C H I V E   ·   O N L I N E   ·   S E C T O R   7 G
```

**Go find something.** 🕵️
```
