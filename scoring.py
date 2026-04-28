"""
scoring.py
----------
Combines all extracted features and threat intelligence into a single
risk score (0–100) and a classification label.

Score breakdown:
  - URL Features:        25 points max
  - Domain Trust:        25 points max
  - Threat Intel APIs:   30 points max
  - Content Analysis:    20 points max
  ─────────────────────
  Total:                100 points max

Higher score = higher risk.
  0–30   → Safe
  31–60  → Suspicious
  61–100 → Phishing
"""

from typing import Tuple


# ─────────────────────────────────────────────
# CLASSIFICATION THRESHOLDS
# ─────────────────────────────────────────────
SAFE_THRESHOLD = 25
SUSPICIOUS_THRESHOLD = 50


# ─────────────────────────────────────────────
# URL FEATURE SCORING  (max 25 pts)
# ─────────────────────────────────────────────

def score_url_features(url_features: dict) -> Tuple[float, dict]:
    """
    Scores URL-level features. Returns (score, breakdown_dict).
    Each check adds penalty points.
    """
    score = 0.0
    breakdown = {}

    # Very long URLs are commonly used to hide the real domain
    length = url_features.get("url_length", 0)
    if length > 100:
        pts = min(5.0, (length - 100) / 20)
        score += pts
        breakdown["url_length_penalty"] = round(pts, 2)

    # Many dots = deep subdomain nesting (common in phishing)
    dots = url_features.get("dot_count", 0)
    if dots > 4:
        pts = min(3.0, (dots - 4) * 0.75)
        score += pts
        breakdown["dot_count_penalty"] = round(pts, 2)

    # Hyphens in domain = typosquatting pattern
    hyphens = url_features.get("hyphen_count", 0)
    if hyphens > 2:
        pts = min(2.0, hyphens * 0.5)
        score += pts
        breakdown["hyphen_penalty"] = round(pts, 2)

    # @ sign in URL redirects victims to attacker's domain
    if url_features.get("at_count", 0) > 0:
        score += 5.0
        breakdown["at_sign"] = 5.0

    # IP address instead of a domain name
    if url_features.get("has_ip_address", 0):
        score += 6.0
        breakdown["ip_address"] = 6.0

    # Suspicious keyword in URL
    if url_features.get("has_suspicious_keyword", 0):
        score += 10.0
        breakdown["suspicious_keyword"] = 10.0

    # Brand keyword with a different domain (impersonation attempt)
    if url_features.get("has_brand_keyword", 0):
        score += 15.0
        breakdown["brand_keyword"] = 15.0

    # High-risk combo: brand + phishing keywords
    if url_features.get("high_risk_combo", 0):
        score += 25.0
        breakdown["high_risk_combo"] = 25.0
    
    # Non-HTTPS connection
    if not url_features.get("is_https", 0):
        score += 10.0
        breakdown["no_https"] = 10.0

    # Suspicious TLD
    if url_features.get("suspicious_tld", 0):
        score += 8.0
        breakdown["suspicious_tld"] = 8.0

    # URL shortener (masks real destination)
    if url_features.get("is_shortened_url", 0):
        score += 3.0
        breakdown["url_shortener"] = 3.0

    # Hex encoding
    if url_features.get("has_hex_encoding", 0):
        score += 2.0
        breakdown["hex_encoding"] = 2.0

    # Percentage encoding (URL tricks)
    pcts = url_features.get("percent_count", 0)
    if pcts > 5:
        score += 2.0
        breakdown["excessive_encoding"] = 2.0

    return min(score, 25.0), breakdown


# ─────────────────────────────────────────────
# DOMAIN TRUST SCORING  (max 25 pts)
# ─────────────────────────────────────────────

def score_domain_features(domain_features: dict, ssl_features: dict) -> Tuple[float, dict]:
    """
    Scores domain-level trust indicators.
    Returns (score, breakdown_dict).
    """
    score = 0.0
    breakdown = {}

    # New domain (phishing domains are typically registered recently)
    age = domain_features.get("domain_age_days", -1)
    if age == -1:
        # Unknown age = suspicious
        score += 8.0
        breakdown["unknown_domain_age"] = 8.0
    elif age < 30:
        score += 10.0
        breakdown["very_new_domain"] = 10.0
    elif age < 180:
        score += 5.0
        breakdown["new_domain"] = 5.0
    elif age < 365:
        score += 2.0
        breakdown["young_domain"] = 2.0

    # No WHOIS information available
    if not domain_features.get("whois_available", 0):
        score += 5.0
        breakdown["no_whois"] = 5.0

    # No registrar info
    if not domain_features.get("registrar_known", 0):
        score += 3.0
        breakdown["unknown_registrar"] = 3.0

    # Domain expiring very soon (could be a burner domain)
    expiry = domain_features.get("domain_expiry_days", -1)
    if 0 < expiry < 30:
        score += 3.0
        breakdown["expiring_soon"] = 3.0

    # SSL certificate issues
    if not ssl_features.get("ssl_valid", 0):
        score += 4.0
        breakdown["invalid_ssl"] = 4.0

    return min(score, 25.0), breakdown


# ─────────────────────────────────────────────
# THREAT INTEL SCORING  (max 30 pts)
# ─────────────────────────────────────────────

def score_threat_intel(threat_features: dict) -> Tuple[float, dict]:
    """
    Scores results from external threat intelligence APIs.
    Returns (score, breakdown_dict).
    """
    score = 0.0
    breakdown = {}

    # Google Safe Browsing hit = very high risk
    if threat_features.get("gsb_threat_found", False):
        score += 20.0
        threat_type = threat_features.get("gsb_threat_type", "UNKNOWN")
        breakdown["gsb_threat"] = f"20.0 ({threat_type})"

    # PhishTank confirmed phishing
    if threat_features.get("pt_is_phishing", False):
        score += 20.0
        breakdown["phishtank_phishing"] = 20.0

    # VirusTotal malicious detections
    vt_malicious = threat_features.get("vt_malicious_count", 0)
    vt_total = threat_features.get("vt_total_engines", 0)
    if vt_total > 0 and vt_malicious > 0:
        ratio = vt_malicious / vt_total
        pts = min(15.0, ratio * 30)
        score += pts
        breakdown["virustotal_detections"] = f"{round(pts,2)} ({vt_malicious}/{vt_total} engines)"

    return min(score, 30.0), breakdown


# ─────────────────────────────────────────────
# CONTENT ANALYSIS SCORING  (max 20 pts)
# ─────────────────────────────────────────────

def score_content_features(content_features: dict) -> Tuple[float, dict]:
    """
    Scores webpage content-based indicators.
    Returns (score, breakdown_dict).
    """
    score = 0.0
    breakdown = {}

    # Page is unreachable — could indicate takedown or bot blocking
    if not content_features.get("page_reachable", 0):
        score += 2.0
        breakdown["page_unreachable"] = 2.0
        return min(score, 20.0), breakdown

    # Password field on a suspicious-looking page
    if content_features.get("has_password_field", 0):
        score += 6.0
        breakdown["password_field"] = 6.0

    # Login form detected
    if content_features.get("has_login_form", 0):
        score += 3.0
        breakdown["login_form"] = 3.0

    # Form submits data to an external (different) domain
    if content_features.get("external_form_action", 0):
        score += 8.0
        breakdown["external_form_action"] = 8.0

    # Brand impersonation (page content mentions major brand but URL differs)
    if content_features.get("brand_impersonation", 0):
        score += 5.0
        breakdown["brand_impersonation"] = 5.0

    # Many hidden form fields (data harvesting)
    if content_features.get("has_hidden_fields", 0):
        score += 2.0
        breakdown["hidden_fields"] = 2.0

    # Obfuscated JavaScript
    if content_features.get("has_suspicious_script", 0):
        score += 4.0
        breakdown["suspicious_script"] = 4.0

    return min(score, 20.0), breakdown


# ─────────────────────────────────────────────
# MASTER SCORING FUNCTION
# ─────────────────────────────────────────────

def calculate_risk_score(
    url_features: dict,
    domain_features: dict,
    ssl_features: dict,
    threat_features: dict,
    content_features: dict
) -> dict:
    """
    Combines all feature scores into a final risk score and classification.

    Returns a comprehensive result dict with:
      - risk_score (0–100)
      - classification ("Safe" / "Suspicious" / "Phishing")
      - score_breakdown (per-category scores and penalty reasons)
    """
    url_score, url_bd = score_url_features(url_features)
    domain_score, domain_bd = score_domain_features(domain_features, ssl_features)
    threat_score, threat_bd = score_threat_intel(threat_features)
    content_score, content_bd = score_content_features(content_features)

    total = url_score + domain_score + threat_score + content_score
    total = round(min(total, 100.0), 2)

    # Determine classification
    if total <= SAFE_THRESHOLD:
        classification = "Safe"
        risk_level = "low"
    elif total <= SUSPICIOUS_THRESHOLD:
        classification = "Suspicious"
        risk_level = "medium"
    else:
        classification = "Phishing"
        risk_level = "high"

    return {
        "risk_score": total,
        "classification": classification,
        "risk_level": risk_level,
        "score_breakdown": {
            "url_features": {
                "score": round(url_score, 2),
                "max": 25,
                "penalties": url_bd
            },
            "domain_trust": {
                "score": round(domain_score, 2),
                "max": 25,
                "penalties": domain_bd
            },
            "threat_intel": {
                "score": round(threat_score, 2),
                "max": 30,
                "penalties": threat_bd
            },
            "content_analysis": {
                "score": round(content_score, 2),
                "max": 20,
                "penalties": content_bd
            }
        }
    }
