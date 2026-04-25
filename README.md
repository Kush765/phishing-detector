# PhishGuard — URL-Based Phishing Detection System
> A modular, production-ready phishing detection system with real-time analysis, threat intelligence, and a live dashboard.

---

## 📁 Project Structure

```
phishing_detector/
│
├── app.py                  # Flask REST API + serves dashboard
├── feature_extraction.py   # URL / domain / SSL / content analysis
├── api_check.py            # Google Safe Browsing, PhishTank, VirusTotal
├── scoring.py              # Risk scoring engine (0–100)
├── database.py             # SQLite storage & analytics queries
├── dashboard.py            # Inline HTML/JS dashboard frontend
├── test_urls.py            # CLI test script (no Flask needed)
├── requirements.txt        # Python dependencies
└── phishing_logs.db        # Auto-created SQLite database
```

---

## ⚡ Quick Start

### 1. Create a virtual environment
```bash
python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. (Optional) Configure API keys
Create a `.env` file or set environment variables:
```bash
export GSB_API_KEY="your_google_safe_browsing_key"
export PHISHTANK_API_KEY="your_phishtank_key"
export VIRUSTOTAL_API_KEY="your_virustotal_key"
```
> **Note:** The system works without real API keys — it uses mock responses and still scores based on URL features, WHOIS, SSL, and content analysis.

### 4. Start the server
```bash
python app.py
```

### 5. Open the dashboard
Visit → **http://localhost:5000**

---

## 🧪 CLI Testing (no server needed)

```bash
# Test all sample URLs
python test_urls.py

# Test a specific URL
python test_urls.py --url https://suspicious-site.tk

# Get raw JSON output
python test_urls.py --url https://example.com --json

# Verbose mode (shows all extracted features)
python test_urls.py --url https://example.com --verbose
```

---

## 🔌 API Endpoints

| Method | Endpoint        | Description                          |
|--------|-----------------|--------------------------------------|
| POST   | `/api/scan`     | Analyze a URL → returns full report  |
| GET    | `/api/history`  | Last 50 scanned URLs                 |
| GET    | `/api/stats`    | Aggregate detection counts           |
| GET    | `/api/daily`    | Daily counts for the last 14 days    |
| GET    | `/`             | Interactive HTML dashboard           |

### POST `/api/scan` example
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal-login-secure.tk/verify"}'
```

```json
{
  "url": "http://paypal-login-secure.tk/verify",
  "risk_score": 74.5,
  "classification": "Phishing",
  "risk_level": "high",
  "score_breakdown": {
    "url_features":      {"score": 14.0, "max": 25, "penalties": {...}},
    "domain_trust":      {"score": 23.0, "max": 25, "penalties": {...}},
    "threat_intel":      {"score": 0.0,  "max": 30, "penalties": {}},
    "content_analysis":  {"score": 17.5, "max": 20, "penalties": {...}}
  },
  "analysis_time_seconds": 3.21
}
```

---

## 🧠 How the Scoring Works

| Category         | Max Points | Key Signals                                         |
|------------------|-----------|-----------------------------------------------------|
| URL Features     | 25        | Length, IP address, suspicious TLDs, keywords, @   |
| Domain Trust     | 25        | Domain age, WHOIS availability, SSL validity        |
| Threat Intel     | 30        | Google Safe Browsing, PhishTank, VirusTotal         |
| Content Analysis | 20        | Login forms, brand impersonation, suspicious JS     |
| **Total**        | **100**   |                                                     |

**Classification:**
- `0–30`   → ✅ **Safe**
- `31–60`  → ⚠️ **Suspicious**
- `61–100` → 🚨 **Phishing**

---

## 🧪 Sample Test URLs

```
# Safe
https://google.com
https://github.com
https://wikipedia.org

# Suspicious
http://bit.ly/3xfakelink
http://192.168.0.1/login

# Phishing (fabricated)
http://paypal-secure-verify-account.tk/login
http://apple-id-verify-suspended.ml/signin
http://amazon-security-alert.xyz/account/suspend
```

---

## 🔑 Getting Free API Keys

| API                    | Free Tier     | Link                                                  |
|------------------------|---------------|-------------------------------------------------------|
| Google Safe Browsing   | 10k req/day   | https://developers.google.com/safe-browsing           |
| PhishTank              | Unlimited     | https://www.phishtank.com/api_info.php                |
| VirusTotal             | 1k req/day    | https://www.virustotal.com/gui/my-apikey              |

---

## 📦 Module Overview

| File                    | Role                                                |
|-------------------------|-----------------------------------------------------|
| `feature_extraction.py` | Extracts 30+ URL, domain, SSL, and content signals  |
| `api_check.py`          | Calls external threat intelligence APIs             |
| `scoring.py`            | Combines features → weighted risk score (0–100)     |
| `database.py`           | SQLite read/write for scan history & analytics      |
| `dashboard.py`          | Self-contained HTML/JS dashboard (served by Flask)  |
| `app.py`                | Flask app — wires everything together               |
| `test_urls.py`          | CLI runner — test without starting the server       |
