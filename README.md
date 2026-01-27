<p align="center">
  <img src="screenshots/logo_diogenes.png" alt="DIOGENES" width="300">
</p>

<h1 align="center">DIOGENES v1.1</h1>
<p align="center"><i>High-Performance Web Security Scanner for Developers</i></p>

---

## 🚀 Features

- **XSS Detection** - Reflected, Stored, DOM-based
- **SQL Injection** - Error patterns + DB fingerprinting
- **CSRF** - Missing token detection
- **SSRF** - Server-side request forgery
- **IDOR** - Access control issues (supports JWT/API keys)
- **Concurrent Scanning** - 3-5x faster with ThreadPoolExecutor
- **Rate Limiting** - Configurable delays to prevent bans
- **Smart Crawling** - SPA support with JS endpoint extraction


## 🏛️ Philosophy

> *Inspired by Diogenes of Sinope — questioning assumptions and exposing weak logic.*

**DIOGENES** does not shout.  
It does not guess.

It **observes**.  
It **compares**.  
It **reasons**.

---

## 📦 Installation

```bash
git clone https://github.com/abdorhl/diogenes.git
cd diogenes
pip install -r requirements.txt
```

---

## 🎯 Quick Start

### Basic Scan
```bash
python diogenes.py https://target.com
```

### Fast Scan (10 threads)
```bash
python diogenes.py https://target.com --threads 10
```

### Production Scan (rate limited)
```bash
python diogenes.py https://target.com --delay 1.0 --html report.html
```

### IDOR with JWT
```bash
python diogenes.py https://api.target.com \
  --identity-a user1.json \
  --identity-b user2.json \
  --detectors idor
```

### Targeted Testing
```bash
python diogenes.py https://target.com --endpoints-file endpoints.txt
```

---

## 📸 Screenshots

<p align="center">
  <img src="screenshots/screen1.png" width="800">
  <br><i>CLI Output with Findings</i>
</p>
<p align="center">
  <img src="screenshots/screen2.png" width="800">
  <br><i>CLI Output with Findings</i>
</p>
<p align="center">
  <img src="screenshots/screen3.png" width="800">
  <br><i>HTML Report Dashboard</i>
</p>

<p align="center">
  <img src="screenshots/screen4.png" width="800">
  <br><i>Finding Details</i>
</p>



---

## 🔧 CLI Options

| Flag | Description | Example |
|------|-------------|---------|
| `--depth N` | Crawl depth | `--depth 3` |
| `--delay N` | Delay between requests (seconds) | `--delay 1.0` |
| `--threads N` | Concurrent workers | `--threads 10` |
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

## 📝 Identity File Format (JWT Support)

```json
{
  "cookies": {
    "session": "abc123"
  },
  "headers": {
    "Authorization": "Bearer eyJhbGci...",
    "X-API-Key": "your_key"
  }
}
```

---

## 📊 Performance

| Target Size | Sequential | Concurrent (5 threads) | Speedup |
|-------------|-----------|------------------------|---------|
| 10 endpoints | 45s | 15s | 3x |
| 50 endpoints | 4m 20s | 55s | 4.7x |
| 100 endpoints | 9m 10s | 2m 5s | 4.4x |


## ⚖️ Legal

**Only test systems you own or have explicit permission to test.**

DIOGENES is for:
- ✅ Internal security audits
- ✅ Pre-deployment testing
- ✅ Bug bounty programs (with authorization)
- ✅ Security training

NOT for:
- ❌ Unauthorized testing
- ❌ Malicious attacks


<p align="center">
  <b>Built for developers who want to ship secure code fast 🛡️⚡</b>
</p>


