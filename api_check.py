"""
api_check.py
------------
Real-time threat intelligence lookups using:
  - Google Safe Browsing API
  - PhishTank API
  - VirusTotal (bonus)

All functions handle API failures gracefully and return structured dicts.
Replace MOCK API keys with real ones for production use.
"""

import requests
import hashlib
import json
import os
from typing import Optional

# ─────────────────────────────────────────────
# API KEYS  (set real keys via environment variables or .env)
# ─────────────────────────────────────────────
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GSB_API_KEY", "MOCK_GSB_KEY")
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY", "MOCK_PHISHTANK_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "MOCK_VT_KEY")

# API Endpoints
GSB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
PHISHTANK_ENDPOINT = "https://checkurl.phishtank.com/checkurl/"
VIRUSTOTAL_ENDPOINT = "https://www.virustotal.com/api/v3/urls"

# ─────────────────────────────────────────────
# GOOGLE SAFE BROWSING
# ─────────────────────────────────────────────

def check_google_safe_browsing(url: str) -> dict:
    """
    Queries Google Safe Browsing API v4 to check if URL is a known threat.
    
    Returns:
        {
          "gsb_checked": bool,
          "gsb_threat_found": bool,
          "gsb_threat_type": str or None,
          "gsb_error": str or None
        }
    """
    result = {
        "gsb_checked": False,
        "gsb_threat_found": False,
        "gsb_threat_type": None,
        "gsb_error": None,
    }

    # Skip actual call if using mock key
    if GOOGLE_SAFE_BROWSING_API_KEY == "MOCK_GSB_KEY":
        result["gsb_error"] = "Mock key — skipping live GSB lookup"
        return result

    payload = {
        "client": {
            "clientId": "phishing-detector",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        resp = requests.post(
            f"{GSB_ENDPOINT}?key={GOOGLE_SAFE_BROWSING_API_KEY}",
            json=payload,
            timeout=6
        )
        result["gsb_checked"] = True

        if resp.status_code == 200:
            data = resp.json()
            matches = data.get("matches", [])
            if matches:
                result["gsb_threat_found"] = True
                result["gsb_threat_type"] = matches[0].get("threatType", "UNKNOWN")
        else:
            result["gsb_error"] = f"HTTP {resp.status_code}"

    except requests.exceptions.Timeout:
        result["gsb_error"] = "Request timed out"
    except Exception as e:
        result["gsb_error"] = str(e)

    return result


# ─────────────────────────────────────────────
# PHISHTANK
# ─────────────────────────────────────────────

def check_phishtank(url: str) -> dict:
    """
    Queries PhishTank API to see if the URL is a known phishing URL.
    
    Returns:
        {
          "pt_checked": bool,
          "pt_is_phishing": bool,
          "pt_verified": bool,
          "pt_error": str or None
        }
    """
    result = {
        "pt_checked": False,
        "pt_is_phishing": False,
        "pt_verified": False,
        "pt_error": None,
    }

    if PHISHTANK_API_KEY == "MOCK_PHISHTANK_KEY":
        result["pt_error"] = "Mock key — skipping live PhishTank lookup"
        return result

    try:
        payload = {
            "url": url,
            "format": "json",
            "app_key": PHISHTANK_API_KEY
        }
        resp = requests.post(
            PHISHTANK_ENDPOINT,
            data=payload,
            timeout=6,
            headers={"User-Agent": "phishing-detector/1.0"}
        )
        result["pt_checked"] = True

        if resp.status_code == 200:
            data = resp.json()
            results = data.get("results", {})
            result["pt_is_phishing"] = results.get("in_database", False)
            result["pt_verified"] = results.get("verified", False)
        else:
            result["pt_error"] = f"HTTP {resp.status_code}"

    except requests.exceptions.Timeout:
        result["pt_error"] = "Request timed out"
    except Exception as e:
        result["pt_error"] = str(e)

    return result


# ─────────────────────────────────────────────
# VIRUSTOTAL (Bonus integration)
# ─────────────────────────────────────────────

def check_virustotal(url: str) -> dict:
    """
    Submits URL to VirusTotal and retrieves detection ratio.
    Uses URL ID (base64 encoded URL) for the lookup.
    
    Returns:
        {
          "vt_checked": bool,
          "vt_malicious_count": int,
          "vt_total_engines": int,
          "vt_error": str or None
        }
    """
    result = {
        "vt_checked": False,
        "vt_malicious_count": 0,
        "vt_total_engines": 0,
        "vt_error": None,
    }

    if VIRUSTOTAL_API_KEY == "MOCK_VT_KEY":
        result["vt_error"] = "Mock key — skipping live VirusTotal lookup"
        return result

    try:
        import base64
        # VirusTotal URL ID = base64url-encoded URL (no padding)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        resp = requests.get(
            f"{VIRUSTOTAL_ENDPOINT}/{url_id}",
            headers=headers,
            timeout=8
        )
        result["vt_checked"] = True

        if resp.status_code == 200:
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            result["vt_malicious_count"] = stats.get("malicious", 0)
            result["vt_total_engines"] = sum(stats.values())
        elif resp.status_code == 404:
            # URL not in VT database yet — not necessarily safe
            result["vt_error"] = "URL not in VirusTotal database"
        else:
            result["vt_error"] = f"HTTP {resp.status_code}"

    except requests.exceptions.Timeout:
        result["vt_error"] = "Request timed out"
    except Exception as e:
        result["vt_error"] = str(e)

    return result


# ─────────────────────────────────────────────
# COMBINED THREAT INTEL
# ─────────────────────────────────────────────

def run_all_threat_checks(url: str) -> dict:
    """
    Runs all three threat intelligence API checks and returns a combined result.
    Any single threat detection sets `threat_detected` to True.
    """
    gsb = check_google_safe_browsing(url)
    pt = check_phishtank(url)
    vt = check_virustotal(url)

    threat_detected = (
        gsb.get("gsb_threat_found", False) or
        pt.get("pt_is_phishing", False) or
        vt.get("vt_malicious_count", 0) > 2
    )

    return {
        **gsb,
        **pt,
        **vt,
        "threat_intel_detected": threat_detected,
    }
