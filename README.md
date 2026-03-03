<p align="center">
  <img src="screenshots/logo_diogenes.png" alt="DIOGENES" width="300">
</p>

<h1 align="center">DIOGENES v1.3</h1>
<p align="center"><i>High-Performance Web Security Scanner for Developers</i></p>

---

## 🏛️ Philosophy

> *Inspired by Diogenes of Sinope — questioning assumptions and exposing weak logic.*

**DIOGENES** does not shout.  
It does not guess.

It **observes**.  
It **compares**.  
It **reasons**.

---

## Features

**Vulnerability Detection**
- **XSS** - 100+ payloads (reflected/stored/DOM), context-aware, WAF evasion, framework-specific (React/Angular/jQuery)
- **SQLi** - Error-based, union-based, blind, DB fingerprinting (MySQL/PostgreSQL/MSSQL/Oracle)
- **Command Injection** - Output-based + time-based blind detection
- **Path Traversal** - Linux/Windows, null byte injection, encoding bypass
- **SSTI** - 8 template engines (Jinja2/ERB/Twig/Smarty/FreeMarker/Velocity/Thymeleaf/Pug)
- **NoSQL Injection** - MongoDB operators, JavaScript injection, auth bypass
- **CORS** - Misconfiguration detection (5 test types)
- **CSRF** - Token validation, strength testing
- **SSRF** - AWS/GCP/Azure metadata, protocol smuggling, localhost bypass
- **XXE** - Classic/SOAP/SVG/XInclude
- **IDOR** - JWT/API key-based access control testing

**Scanning Modes**
- Interactive console (Metasploit-style)
- CLI with multiple profiles (stealth/balanced/aggressive/quick)
- Concurrent scanning (ThreadPoolExecutor)
- Smart crawling (SPA support, JS endpoint extraction)
- Rate limiting + request delay controls

## Installation

```bash
git clone https://github.com/abdorhl/diogenes.git
cd diogenes
pip install -r requirements.txt
```

## Usage

### Interactive Console (Recommended)
```bash
python console.py

# Available modules:
# full              - Full scan (all detectors)
# xss               - XSS only
# sqli              - SQL injection only
# cmd_injection     - Command injection only
# path_traversal    - Path traversal only
# ssti              - SSTI only
# nosql             - NoSQL injection only
# cors              - CORS only
# csrf              - CSRF only
# ssrf              - SSRF only
# xxe               - XXE only
# idor              - IDOR only
# quick             - Quick scan (priority payloads)
# stealth           - Stealth mode
# aggressive        - Aggressive mode

diogenes > use full
diogenes (full) > set TARGET https://target.com
diogenes (full) > set COOKIE session=abc123
diogenes (full) > run
```

### CLI Mode

**Basic scan**
```bash
python diogenes.py https://target.com
```

**Quick scan (60-80% faster, priority payloads only)**
```bash
python diogenes.py https://target.com --quick-scan --threads 10
```

**With authentication**
```bash
python diogenes.py https://target.com --cookie "session=abc123" --header "Authorization: Bearer token"
```

**Configuration file**
```bash
python diogenes.py https://target.com --config examples/config_stealth.json
```

**IDOR testing (requires 2 identities)**
```bash
python diogenes.py https://api.target.com \
  --identity-a user1.json \
  --identity-b user2.json \
  --detectors idor
```

**Scan from endpoint list**
```bash
##g src="screenshots/screen4.png" width="800">
  <br><i>Finding Details</i>
</p>



---

## 🔧 CLI Options

| Flag | Description | Example |
|------|-------------|---------|
| `--profile` | **Scan profile** (stealth/balanced/aggressive/quick) | `--profile stealth` |
| `--config` | **Load config file** | `--config scan.json` |
| `--depth N` | Crawl depth | `--depth 3` |
| `--delay N` | Delay between requests (seconds) | `--delay 1.0` |
| `--threads N` | Concurrent workers | `--threads 10` |
| `--quick-scan` | **Smart early-exit mode** | `--quick-scan` |
| `--no-concurrent` | Sequential mode | `--no-concurrent` |
| `--endpoints-file` | Load endpoints from file | `--endpoints-file api.txt` |
| `--detectors` | Specific detectors | `--detectors xss,sqli` |
| `--cookie` | Session cookies | `--cookie "session=abc"` |
| `--header` | Custom headers | `--header "Auth: Bearer token"` |
| `--identity-a/b` | IDOR testing identities | `--identity-a user1.json` |
| `--output` | Format (table/json) | `--output json` |
| `--html` | HTML report path | `--html report.html` |
| `--verbose` | Verbose logging | `--verbose` |

---

## 🆕 Configuration & Environment Variables

### Using Config Files
```bash
python diogenes.py https://target.com --config examples/config_balanced.json
```

### Environment Variables
```bash
export DIOGENES_THREADS=10
export DIOGENES_DELAY=0.5
export DIOGENES_QUICK_SCAN=true
python diogenes.py https://target.com
```

### Available Profiles
- **stealth** - Slow, careful, avoids detection (delay 1s, 2 threads)
- **balanced** - Default recommended settings (delay 0.3s, 5 threads)
- **aggressive** - Fast and thorough (no delay, 10 threads)
- **quick** - Fastest scan with early-exit (8 threads, max 200 URLs)
- **deep** - Comprehensive crawl (depth 5, max 2000 URLs)

---

## Legal

**Only test systems you own or have written authorization to test.**

For: Internal audits, pre-deployment testing, authorized bug bounties, security training.
Not for: Unauthorized testing or malicious purposes.

## License

Use responsibly.
