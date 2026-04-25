"""
app.py
------
Flask REST API backend for the phishing detection system.

Endpoints:
  POST /api/scan          → Analyze a URL and return risk score
  GET  /api/history       → Last 50 scanned URLs
  GET  /api/stats         → Aggregate detection statistics
  GET  /api/daily         → Daily scan counts for chart
  GET  /                  → Serves the frontend dashboard
"""

import concurrent.futures
import time
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS

from feature_extraction import (
    extract_url_features,
    get_domain_features,
    check_ssl_certificate,
    analyze_page_content,
)
from api_check import run_all_threat_checks
from scoring import calculate_risk_score
from database import init_db, save_scan, get_recent_scans, get_stats, get_daily_counts
from dashboard import DASHBOARD_HTML  # inline HTML dashboard

# ─────────────────────────────────────────────
# APP SETUP
# ─────────────────────────────────────────────
app = Flask(__name__)
CORS(app)  # Allow browser extension / frontend cross-origin requests
init_db()  # Ensure DB tables exist on startup


# ─────────────────────────────────────────────
# CORE SCAN LOGIC
# ─────────────────────────────────────────────

def analyze_url(url: str) -> dict:
    """
    Orchestrates the full pipeline for a single URL:
      1. URL feature extraction
      2. Domain / WHOIS analysis  ┐
      3. SSL check                ├─ run concurrently
      4. Threat Intel APIs        ┘
      5. Page content analysis
      6. Risk score calculation

    Returns the complete analysis dict.
    """
    start = time.time()

    # Normalize URL
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # Step 1 — URL features (fast, no network)
    url_features = extract_url_features(url)

    # Steps 2–4 — Run I/O-heavy checks concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        future_domain = executor.submit(get_domain_features, url)
        future_ssl    = executor.submit(check_ssl_certificate, url)
        future_threat = executor.submit(run_all_threat_checks, url)

        domain_features = future_domain.result()
        ssl_features    = future_ssl.result()
        threat_features = future_threat.result()

    # Step 5 — Content analysis (can be slow for heavy pages)
    content_features = analyze_page_content(url)

    # Step 6 — Score
    scoring_result = calculate_risk_score(
        url_features, domain_features, ssl_features,
        threat_features, content_features
    )

    elapsed = round(time.time() - start, 3)

    result = {
        "url": url,
        **scoring_result,
        "features": {
            "url":     url_features,
            "domain":  domain_features,
            "ssl":     ssl_features,
            "threat":  threat_features,
            "content": content_features,
        },
        "analysis_time_seconds": elapsed
    }

    # Persist to DB
    save_scan(
        url=url,
        risk_score=scoring_result["risk_score"],
        classification=scoring_result["classification"],
        details=result
    )

    return result


# ─────────────────────────────────────────────
# API ROUTES
# ─────────────────────────────────────────────

@app.route("/api/scan", methods=["POST"])
def scan():
    """
    POST /api/scan
    Body: { "url": "https://example.com" }
    Returns: full analysis JSON
    """
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "URL is required"}), 400

    if len(url) > 2000:
        return jsonify({"error": "URL too long"}), 400

    try:
        result = analyze_url(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500


@app.route("/api/history", methods=["GET"])
def history():
    """GET /api/history — Returns last 50 scanned URLs."""
    return jsonify(get_recent_scans(50))


@app.route("/api/stats", methods=["GET"])
def stats():
    """GET /api/stats — Returns aggregate detection stats."""
    return jsonify(get_stats())


@app.route("/api/daily", methods=["GET"])
def daily():
    """GET /api/daily — Returns daily scan counts for the past 14 days."""
    return jsonify(get_daily_counts(14))


@app.route("/", methods=["GET"])
def index():
    """Serves the HTML dashboard."""
    return render_template_string(DASHBOARD_HTML)


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("  Phishing Detection System  |  http://localhost:5000")
    print("=" * 55)
    import os

if __name__ == "__main__":
    print("=" * 55)
    print("  Phishing Detection System")
    print("=" * 55)

    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
