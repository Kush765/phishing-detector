"""
test_urls.py
------------
Standalone CLI script to test the phishing detector without starting Flask.
Runs the full analysis pipeline on a set of sample URLs and prints results.

Usage:
    python test_urls.py
    python test_urls.py --url https://yoursite.com
"""

import sys
import json
import argparse
import concurrent.futures
import time

# ── Import analysis modules
from feature_extraction import (
    extract_url_features,
    get_domain_features,
    check_ssl_certificate,
    analyze_page_content,
)
from api_check import run_all_threat_checks
from scoring import calculate_risk_score

# ─────────────────────────────────────────────
# SAMPLE TEST URLS
# ─────────────────────────────────────────────
SAMPLE_URLS = [
    # ── Likely SAFE
    "https://www.google.com",
    "https://github.com",
    "https://www.wikipedia.org",

    # ── Likely SUSPICIOUS (newly registered / poor reputation)
    "http://bit.ly/3xfakelink",
    "http://192.168.0.1/login",

    # ── Likely PHISHING (fabricated domains)
    "http://paypal-secure-verify-account.tk/login?redirect=update",
    "http://apple-id-verify-suspended.ml/signin",
    "http://www.amazon-security-alert.xyz/account/suspend",
]


# ─────────────────────────────────────────────
# CORE ANALYSIS RUNNER
# ─────────────────────────────────────────────

def analyze(url: str, verbose: bool = False) -> dict:
    """Runs the full detection pipeline on a single URL."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    start = time.time()
    url_features = extract_url_features(url)

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        f_domain  = ex.submit(get_domain_features, url)
        f_ssl     = ex.submit(check_ssl_certificate, url)
        f_threat  = ex.submit(run_all_threat_checks, url)
        domain_features  = f_domain.result()
        ssl_features     = f_ssl.result()
        threat_features  = f_threat.result()

    content_features = analyze_page_content(url)

    result = calculate_risk_score(
        url_features, domain_features, ssl_features,
        threat_features, content_features
    )
    result["url"] = url
    result["time"] = round(time.time() - start, 2)

    if verbose:
        result["features"] = {
            "url":     url_features,
            "domain":  domain_features,
            "ssl":     ssl_features,
            "threat":  threat_features,
            "content": content_features,
        }
    return result


# ─────────────────────────────────────────────
# PRETTY PRINTER
# ─────────────────────────────────────────────

COLOR = {
    "Safe":       "\033[92m",
    "Suspicious": "\033[93m",
    "Phishing":   "\033[91m",
    "reset":      "\033[0m",
    "bold":       "\033[1m",
    "dim":        "\033[2m",
}

def print_result(r: dict):
    c = COLOR.get(r["classification"], "")
    rs = COLOR["reset"]
    b  = COLOR["bold"]
    d  = COLOR["dim"]

    verdict_icon = {"Safe": "✓", "Suspicious": "⚠", "Phishing": "✗"}.get(r["classification"], "?")

    print(f"\n{b}{'─'*60}{rs}")
    print(f"  URL: {d}{r['url'][:80]}{rs}")
    print(f"  Score: {b}{c}{r['risk_score']}/100{rs}  {c}{verdict_icon} {r['classification']}{rs}  ({r['time']}s)")

    bd = r.get("score_breakdown", {})
    for cat, info in bd.items():
        score = info.get("score", 0)
        maxi  = info.get("max", 0)
        pens  = info.get("penalties", {})
        bar_len = int((score / maxi) * 20) if maxi else 0
        bar_fill = "█" * bar_len + "░" * (20 - bar_len)
        print(f"  {cat:<18} [{bar_fill}] {score:>5}/{maxi}")
        for pen, val in pens.items():
            print(f"    {d}+ {pen}: {val}{rs}")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phishing Detector CLI")
    parser.add_argument("--url", help="Single URL to analyze")
    parser.add_argument("--verbose", action="store_true", help="Show raw features")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    urls = [args.url] if args.url else SAMPLE_URLS

    print(f"\n{'='*60}")
    print(f"  PhishGuard — URL Analysis Engine")
    print(f"  Testing {len(urls)} URL(s)…")
    print(f"{'='*60}")

    for url in urls:
        try:
            result = analyze(url, verbose=args.verbose)
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print_result(result)
        except Exception as e:
            print(f"\n  ERROR analyzing {url}: {e}")

    print(f"\n{'─'*60}")
    print("  Done.\n")
