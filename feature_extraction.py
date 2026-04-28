"""
feature_extraction.py
---------------------
Extracts URL-level, domain-level, and structural features from a given URL.
These features feed into the risk scoring engine.
"""

import re
import ssl
import socket
import whois
import requests
import tldextract
from datetime import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# ─────────────────────────────────────────────
# SUSPICIOUS KEYWORD LISTS
# ─────────────────────────────────────────────
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "secure", "update",
    "account", "banking", "confirm", "password", "credential",
    "alert", "suspended", "locked", "unusual", "validate",
    "ebayisapi", "webscr", "paypal", "submit", "recover"
]

BRAND_KEYWORDS = [
    "paypal", "google", "facebook", "apple", "amazon", "microsoft",
    "netflix", "instagram", "twitter", "linkedin", "dropbox",
    "chase", "wellsfargo", "bankofamerica", "citibank", "irs",
    "fedex", "dhl", "ups", "usps"
]


# ─────────────────────────────────────────────
# URL FEATURE EXTRACTION
# ─────────────────────────────────────────────

def extract_url_features(url: str) -> dict:
    """
    Extracts numerical and boolean features from the raw URL string.
    Returns a dictionary of feature_name -> value.
    """
    parsed = urlparse(url)
    extracted = tldextract.extract(url)
    
    features = {}

    # Basic length-based features
    features["url_length"] = len(url)
    features["domain_length"] = len(extracted.domain)
    features["path_length"] = len(parsed.path)

    # Count special characters (common in obfuscated phishing URLs)
    features["dot_count"] = url.count(".")
    features["hyphen_count"] = url.count("-")
    features["at_count"] = url.count("@")          # @ can redirect victims
    features["question_count"] = url.count("?")
    features["equals_count"] = url.count("=")
    features["underscore_count"] = url.count("_")
    features["slash_count"] = url.count("/")
    features["percent_count"] = url.count("%")      # URL encoding tricks
    features["ampersand_count"] = url.count("&")
    features["tilde_count"] = url.count("~")
    features["hash_count"] = url.count("#")

    # Subdomain depth (more subdomains = more suspicious)
    subdomains = extracted.subdomain.split(".") if extracted.subdomain else []
    features["subdomain_depth"] = len([s for s in subdomains if s])

    # Protocol
    features["is_https"] = 1 if parsed.scheme == "https" else 0

    # IP address in URL instead of domain name
    features["has_ip_address"] = 1 if _is_ip_address(extracted.domain or parsed.netloc) else 0

    # Suspicious keyword presence in URL
    url_lower = url.lower()
    features["has_suspicious_keyword"] = 1 if any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS) else 0
# Detect brand impersonation in URL
features["has_brand_keyword"] = 0

domain = extracted.domain.lower()
full_domain = f"{extracted.domain}.{extracted.suffix}".lower()

for brand in BRAND_KEYWORDS:
    if brand in url_lower:
        # Brand present but not actual domain
        if brand != domain:
            features["has_brand_keyword"] = 1

        # Brand not matching full domain
        if brand not in full_domain:
            features["has_brand_keyword"] = 1

        break

    # High-risk combo: brand + phishing keywords
    features["high_risk_combo"] = 1 if (
        features["has_brand_keyword"] and features["has_suspicious_keyword"]
    ) else 0

    # Hex encoding or obfuscation
    features["has_hex_encoding"] = 1 if re.search(r"%[0-9a-fA-F]{2}", url) else 0

    # Presence of port number (non-standard ports are suspicious)
    features["has_port"] = 1 if parsed.port else 0

    # Double slash (//) in path (redirection trick)
    features["double_slash_in_path"] = 1 if "//" in parsed.path else 0

    # URL shortener detection
    shorteners = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly"]
    features["is_shortened_url"] = 1 if any(s in url_lower for s in shorteners) else 0

    # TLD suspiciousness (common in phishing campaigns)
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click"]
    features["suspicious_tld"] = 1 if any(url_lower.endswith(tld) for tld in suspicious_tlds) else 0

    return features


def _is_ip_address(hostname: str) -> bool:
    """Returns True if the hostname is an IPv4 or IPv6 address."""
    ipv4_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"
    )
    # Strip port if present
    hostname = hostname.split(":")[0]
    return bool(ipv4_pattern.match(hostname))


# ─────────────────────────────────────────────
# DOMAIN / WHOIS FEATURES
# ─────────────────────────────────────────────

def get_domain_features(url: str) -> dict:
    """
    Retrieves WHOIS information and domain age.
    Returns domain trust-related features.
    """
    features = {
        "domain_age_days": -1,
        "whois_available": 0,
        "registrar_known": 0,
        "domain_expiry_days": -1,
    }

    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"

    try:
        w = whois.whois(domain)
        features["whois_available"] = 1

        # Domain creation date → age
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            age = (datetime.now() - creation).days
            features["domain_age_days"] = max(age, 0)

        # Domain expiry date → how long until it expires
        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]
        if expiry:
            remaining = (expiry - datetime.now()).days
            features["domain_expiry_days"] = max(remaining, 0)

        # Registrar presence (legitimate sites have known registrars)
        features["registrar_known"] = 1 if w.registrar else 0

    except Exception:
        # WHOIS lookup failed — treat as unknown/suspicious
        pass

    return features


# ─────────────────────────────────────────────
# SSL CERTIFICATE FEATURES
# ─────────────────────────────────────────────

def check_ssl_certificate(url: str) -> dict:
    """
    Attempts to verify SSL certificate validity for the domain.
    Returns certificate-related features.
    """
    features = {
        "ssl_valid": 0,
        "ssl_error": 1,
    }

    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    if extracted.subdomain:
        domain = f"{extracted.subdomain}.{domain}"

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    features["ssl_valid"] = 1
                    features["ssl_error"] = 0
    except ssl.SSLCertVerificationError:
        features["ssl_valid"] = 0
        features["ssl_error"] = 1
    except Exception:
        # Connection failed or timeout — mark as unknown
        features["ssl_valid"] = 0
        features["ssl_error"] = 1

    return features


# ─────────────────────────────────────────────
# CONTENT-BASED FEATURES
# ─────────────────────────────────────────────

def analyze_page_content(url: str, timeout: int = 8) -> dict:
    """
    Fetches the webpage and performs content-level analysis:
    - Login / password form detection
    - Brand impersonation signals
    - Suspicious JavaScript patterns
    - Page title and meta description
    """
    features = {
        "page_reachable": 0,
        "has_login_form": 0,
        "has_password_field": 0,
        "has_hidden_fields": 0,
        "has_suspicious_script": 0,
        "brand_impersonation": 0,
        "external_form_action": 0,
        "page_title": "",
        "form_count": 0,
    }

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
        )
    }

    try:
        resp = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True)
        features["page_reachable"] = 1
        soup = BeautifulSoup(resp.text, "html.parser")

        # ── Title
        title_tag = soup.find("title")
        features["page_title"] = title_tag.text.strip()[:120] if title_tag else ""

        # ── Forms analysis
        forms = soup.find_all("form")
        features["form_count"] = len(forms)

        for form in forms:
            action = form.get("action", "").lower()

            # Check if form posts to an external domain
            parsed_url = urlparse(url)
            parsed_action = urlparse(action)
            if parsed_action.netloc and parsed_action.netloc != parsed_url.netloc:
                features["external_form_action"] = 1

            # Check for password fields → strong phishing signal
            if form.find("input", {"type": "password"}):
                features["has_password_field"] = 1
                features["has_login_form"] = 1

            # Check for text/email inputs (login form indicators)
            email_inputs = form.find_all("input", {"type": ["email", "text"]})
            if email_inputs:
                features["has_login_form"] = 1

        # ── Hidden input fields (data exfiltration technique)
        hidden = soup.find_all("input", {"type": "hidden"})
        features["has_hidden_fields"] = 1 if len(hidden) > 3 else 0

        # ── Suspicious JavaScript patterns
        scripts = soup.find_all("script")
        script_text = " ".join(s.get_text() for s in scripts).lower()
        suspicious_js_patterns = [
            "document.cookie", "eval(", "unescape(", "fromcharcode",
            "atob(", "window.location", "document.write("
        ]
        features["has_suspicious_script"] = 1 if any(
            pat in script_text for pat in suspicious_js_patterns
        ) else 0

        # ── Brand impersonation detection (page content mentions known brands
        #    but domain is different)
        page_text = soup.get_text().lower()
        extracted = tldextract.extract(url)
        for brand in BRAND_KEYWORDS:
            if brand in page_text and brand not in extracted.domain:
                features["brand_impersonation"] = 1
                break

    except requests.exceptions.Timeout:
        pass  # Page unreachable within timeout
    except Exception:
        pass  # Any fetch error — keep defaults

    return features
