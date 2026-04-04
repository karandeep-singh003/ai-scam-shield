"""
URL Heuristic Analysis Engine
==============================
Analyzes URLs for phishing indicators using structural rules.

IMPORTANT DESIGN FIX:
- Do NOT treat arbitrary plain text as a URL
- Only analyze input that actually looks like a real URL or domain
- Return url_present=True only when a real URL/domain was analyzed
"""

import re
from urllib.parse import urlparse

TRUSTED_DOMAINS = {
    "sbi.co.in", "onlinesbi.sbi", "yonobusiness.sbi",
    "hdfcbank.com", "netbanking.hdfc.com",
    "icicibank.com", "axisbank.com", "kotak.com",
    "paytm.com", "phonepe.com", "googlepay.com",
    "bhimupi.org.in", "npci.org.in",
    "amazon.in", "flipkart.com", "irctc.co.in",
    "incometax.gov.in", "uidai.gov.in", "india.gov.in",
    "rbi.org.in", "sebi.gov.in",
}

IMPERSONATED_BRANDS = [
    "sbi", "hdfc", "icici", "axis", "kotak", "pnb",
    "paytm", "phonepe", "googlepay", "gpay", "bhim",
    "amazon", "flipkart", "jio", "airtel",
    "incometax", "uidai", "aadhaar", "irctc", "npci",
    "yono", "netbanking",
]

SUSPICIOUS_TLDS = {
    "xyz", "info", "online", "site", "click", "loan",
    "tk", "ml", "ga", "cf", "gq", "top", "pw", "cc",
    "su", "icu", "vip", "work", "rest", "fun", "space",
    "website", "digital", "link", "live", "host", "ru", "cn",
}

PHISHING_KEYWORDS = [
    "verify", "update", "secure", "login", "signin",
    "account", "confirm", "kyc", "otp", "pin",
    "blocked", "suspend", "urgent", "claim", "reward",
    "free", "winner", "prize", "cashback", "refund",
    "netbanking", "wallet", "payment",
]


def _empty_result() -> dict:
    return {
        "score": 0,
        "reasons": [],
        "is_trusted": False,
        "domain": "",
        "url_present": False,
        "category": "No URL Detected"
    }


def _looks_like_url_or_domain(value: str) -> bool:
    """
    Strict guard to prevent arbitrary text from being treated as a URL.

    Accept:
    - https://example.com
    - http://example.com
    - www.example.com
    - example.com
    - sbi-kyc.xyz

    Reject:
    - "HDFC: Rs 1500 debited..."
    - "Your OTP is 123456"
    - random sentences
    """
    if not value or not value.strip():
        return False

    value = value.strip()

    # Reject obvious whitespace-containing sentences
    # Real standalone URL/domain input should not contain spaces
    if " " in value:
        return False

    # Accept if full URL
    if value.startswith(("http://", "https://")):
        return True

    # Accept if starts with www.
    if value.lower().startswith("www."):
        return True

    # Accept domain-like pattern:
    # - at least one dot
    # - valid-ish chars only
    # - TLD 2+ chars
    domain_pattern = re.compile(
        r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]*\.[a-zA-Z]{2,}$'
    )
    return bool(domain_pattern.match(value))


def analyze_url(url: str) -> dict:
    """
    Analyze a URL for phishing indicators.
    Returns score 0-100, reasons, trust status, and domain info.
    """

    if not url or not url.strip():
        return _empty_result()

    url = url.strip()

    # ── CRITICAL FIX: reject non-URL text immediately ─────────────────────
    if not _looks_like_url_or_domain(url):
        return {
            "score": 0,
            "reasons": ["Input is not a valid standalone URL/domain"],
            "is_trusted": False,
            "domain": "",
            "url_present": False,
            "category": "Invalid or Non-URL Input"
        }

    # Normalize: if scheme missing, add http:// for parsing only
    normalized_url = url
    if not normalized_url.startswith(("http://", "https://")):
        normalized_url = "http://" + normalized_url

    try:
        parsed = urlparse(normalized_url)
    except Exception:
        return {
            "score": 20,
            "reasons": ["Could not parse URL structure"],
            "is_trusted": False,
            "domain": "",
            "url_present": False,
            "category": "Malformed URL"
        }

    raw_score = 0
    reasons = []
    is_trusted = False

    hostname = (parsed.hostname or "").lower()
    clean_host = hostname.replace("www.", "")

    if not clean_host:
        return {
            "score": 20,
            "reasons": ["URL missing valid hostname"],
            "is_trusted": False,
            "domain": "",
            "url_present": False,
            "category": "Malformed URL"
        }

    # ── Check 1: Trusted domain ───────────────────────────────────────────
    for trusted in TRUSTED_DOMAINS:
        if clean_host == trusted or clean_host.endswith("." + trusted):
            return {
                "score": 0,
                "reasons": [f"Trusted domain: {clean_host}"],
                "is_trusted": True,
                "domain": clean_host,
                "url_present": True,
                "category": "Trusted Domain"
            }

    # ── Check 2: IP address as host ───────────────────────────────────────
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname):
        raw_score += 70
        reasons.append("Uses IP address as host — legitimate sites use domain names")

    # ── Check 3: Suspicious TLD ───────────────────────────────────────────
    parts = clean_host.split(".")
    tld = parts[-1].lower() if parts else ""
    if tld in SUSPICIOUS_TLDS:
        raw_score += 40
        reasons.append(f"Suspicious domain extension: .{tld}")

    # ── Check 4: Brand impersonation in hostname ──────────────────────────
    for brand in IMPERSONATED_BRANDS:
        if brand in clean_host:
            is_legit = any(
                clean_host == t or clean_host.endswith("." + t)
                for t in TRUSTED_DOMAINS
            )
            if not is_legit:
                raw_score += 55
                reasons.append(
                    f"Domain impersonates '{brand}' but is not the official website"
                )
                break

    # ── Check 5: Long domain ──────────────────────────────────────────────
    if len(clean_host) > 40:
        raw_score += 25
        reasons.append(f"Unusually long domain name ({len(clean_host)} chars)")

    # ── Check 6: Hyphen abuse ─────────────────────────────────────────────
    hyphen_count = clean_host.count("-")
    if hyphen_count >= 3:
        raw_score += 35
        reasons.append(f"Excessive hyphens in domain ({hyphen_count}) — typosquatting pattern")
    elif hyphen_count >= 2:
        raw_score += 20
        reasons.append("Multiple hyphens in domain — possible typosquatting")

    # ── Check 7: Phishing keywords in path/query ──────────────────────────
    path_query = ((parsed.path or "") + " " + (parsed.query or "")).lower()
    matched_kw = [kw for kw in PHISHING_KEYWORDS if kw in path_query]
    if len(matched_kw) >= 3:
        raw_score += 35
        reasons.append(f"URL path contains phishing keywords: {', '.join(matched_kw[:3])}")
    elif len(matched_kw) >= 1:
        raw_score += 15
        reasons.append(f"URL path contains suspicious keyword: {matched_kw[0]}")

    # ── Check 8: Very long full URL ───────────────────────────────────────
    if len(normalized_url) > 150:
        raw_score += 20
        reasons.append(f"Very long URL ({len(normalized_url)} chars) — may be obfuscating destination")

    # ── Check 9: HTTP on financial-looking site ───────────────────────────
    if parsed.scheme == "http":
        financial = ["bank", "pay", "upi", "wallet", "sbi", "hdfc", "icici", "paytm"]
        if any(kw in clean_host for kw in financial):
            raw_score += 30
            reasons.append("Financial-looking site using HTTP instead of HTTPS")

    # ── Check 10: Subdomain abuse ─────────────────────────────────────────
    # Example: sbi.secure-login.xyz  -> suspicious
    for brand in IMPERSONATED_BRANDS:
        if clean_host.startswith(brand + "."):
            root = ".".join(clean_host.split(".")[-2:])
            if root not in TRUSTED_DOMAINS:
                raw_score += 65
                reasons.append(
                    f"Uses '{brand}' as subdomain on untrusted domain — subdomain phishing"
                )
                break

    final_score = min(100, max(0, raw_score))

    category = "Likely Safe URL" if final_score < 25 else "Phishing URL"

    return {
        "score": final_score,
        "reasons": reasons,
        "is_trusted": is_trusted,
        "domain": clean_host,
        "url_present": True,
        "category": category
    }
