"""
Rule-Based Detection Engine
============================
Detects scams using hand-crafted keyword patterns and regex rules.

WHY RULES FIRST?
- Rules are explainable — we can tell users exactly WHY something is flagged
- Rules are instant — no model loading needed
- Rules catch high-confidence scams with zero false negatives on known patterns
- Rules complement ML — ML catches novel patterns, rules catch known ones

SCORING:
Each matched pattern adds a weight to the raw score.
Raw score is normalized to 0-100 before returning.
"""

import re
from app.utils.text_cleaner import (
    clean_text, contains_any, contains_all,
    extract_urls, has_urgency_indicators, extract_amounts
)


# ══════════════════════════════════════════════════════════════════════════
# PATTERN LIBRARY
# Each entry: (display_reason, score_weight)
# score_weight is how much this pattern contributes (out of 100 total)
# ══════════════════════════════════════════════════════════════════════════

# ── KYC scam patterns ─────────────────────────────────────────────────────
KYC_PATTERNS = {
    "keywords": [
        "kyc", "kyc update", "kyc verification", "kyc pending",
        "complete kyc", "kyc expire", "kyc expiry", "video kyc",
        "aadhaar kyc", "pan kyc", "ekyc"
    ],
    "reason": "Contains KYC-related scam language",
    "weight": 30
}

# ── OTP scam patterns ─────────────────────────────────────────────────────
OTP_PATTERNS = {
    "keywords": [
        "share otp", "send otp", "enter otp", "provide otp",
        "otp to our", "otp with our", "otp for verification",
        "share the otp", "give otp"
    ],
    "reason": "Asks user to share OTP — legitimate services never ask for OTP",
    "weight": 70
}

# ── Account blocked / urgent banking scams ────────────────────────────────
ACCOUNT_BLOCK_PATTERNS = {
    "keywords": [
        "account blocked", "account suspended", "account deactivated",
        "account will be closed", "account will be suspended",
        "account on hold", "temporarily blocked", "access restricted",
        "service suspended", "account frozen"
    ],
    "reason": "Claims account is blocked to create panic — classic social engineering",
    "weight": 35
}

# ── Fake refund scams ─────────────────────────────────────────────────────
REFUND_PATTERNS = {
    "keywords": [
        "pending refund", "refund pending", "unclaimed refund",
        "income tax refund", "tds refund", "electricity refund",
        "insurance refund", "refund has been initiated",
        "refund of rs", "refund amount"
    ],
    "reason": "Fake refund claim used to trick users into sharing payment details",
    "weight": 40
}

# ── UPI PIN harvest patterns ──────────────────────────────────────────────
UPI_PIN_PATTERNS = {
    "keywords": [
        "enter upi pin", "enter your upi pin", "upi pin to receive",
        "pin to accept", "enter pin to get", "share upi pin",
        "provide upi pin", "input upi pin", "enter pin to claim"
    ],
    "reason": "Asks for UPI PIN to 'receive' money — you NEVER need PIN to receive",
    "weight": 90
}

# ── Reward / cashback / prize scams ──────────────────────────────────────
REWARD_PATTERNS = {
    "keywords": [
        "you have won", "you won", "congratulations you",
        "lucky winner", "selected for reward", "cash prize",
        "lottery winner", "kbc winner", "spin and win",
        "lucky draw", "gift voucher worth", "free cashback",
        "claim your prize", "claim your reward", "you are selected"
    ],
    "reason": "Fake prize or reward used to extract personal/banking details",
    "weight": 45
}

# ── Customer support impersonation ────────────────────────────────────────
SUPPORT_IMPERSONATION = {
    "keywords": [
        "customer care executive", "bank executive", "from sbi",
        "from hdfc", "from icici", "from paytm team",
        "phonepe support", "google pay team", "our executive will",
        "call our helpline", "contact our support"
    ],
    "reason": "Impersonates bank or wallet customer support",
    "weight": 35
}

# ── Credential harvesting ─────────────────────────────────────────────────
CREDENTIAL_PATTERNS = {
    "keywords": [
        "share your password", "enter your password",
        "share your card number", "enter card details",
        "cvv number", "share cvv", "card expiry",
        "net banking password", "login credentials",
        "share account number", "account number and ifsc"
    ],
    "reason": "Attempts to harvest banking credentials",
    "weight": 80
}

# ── Aadhaar / PAN data harvesting ────────────────────────────────────────
IDENTITY_PATTERNS = {
    "keywords": [
        "share aadhaar", "send aadhaar", "aadhaar number",
        "pan card details", "send pan", "share pan number",
        "aadhaar otp", "aadhaar verification link",
        "link aadhaar", "pan aadhaar link"
    ],
    "reason": "Attempts to collect Aadhaar or PAN identity details",
    "weight": 55
}

# ── Suspicious request to send money first ────────────────────────────────
ADVANCE_FEE_PATTERNS = {
    "keywords": [
        "send rs 1", "pay rs 1", "deposit rs",
        "registration fee", "processing fee", "small fee",
        "send small amount", "pay to receive", "advance payment",
        "token amount", "nominal fee to claim"
    ],
    "reason": "Advance fee fraud — asks you to send money first to receive a larger amount",
    "weight": 65
}

# ── Phishing link indicators ──────────────────────────────────────────────
PHISHING_LINK_PATTERNS = {
    "keywords": [
        "click here to verify", "click to update",
        "verify your account", "update your details",
        "login to secure", "verify now at",
        "click the link below", "tap here immediately"
    ],
    "reason": "Contains phishing call-to-action directing to suspicious link",
    "weight": 40
}

# ── Suspicious TLDs in message text ──────────────────────────────────────
SUSPICIOUS_TLD_REGEX = re.compile(
    r'https?://[^\s]*\.(xyz|info|online|site|click|loan|'
    r'tk|ml|ga|cf|gq|top|pw|cc|su|icu|vip|work|rest|fun|'
    r'space|website|digital|link|live|host|ru|cn)\b',
    re.IGNORECASE
)

# ── IP address as URL host ────────────────────────────────────────────────
IP_URL_REGEX = re.compile(
    r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
)

# ── Combination patterns (require multiple signals together) ──────────────
# These fire only when BOTH conditions are met — higher confidence
COMBINATION_RULES = [
    {
        "conditions": ["upi", "pin", "receive"],
        "reason": "Classic UPI PIN harvest: 'enter PIN to receive money' is always a scam",
        "weight": 95
    },
    {
        "conditions": ["otp", "share", "bank"],
        "reason": "Asks to share OTP with someone claiming to be from a bank",
        "weight": 85
    },
    {
        "conditions": ["kyc", "blocked", "immediately"],
        "reason": "KYC urgency scam: threatens account block to force immediate action",
        "weight": 75
    },
    {
        "conditions": ["refund", "upi", "pin"],
        "reason": "Fake refund requiring UPI PIN — refunds never need your PIN",
        "weight": 90
    },
    {
        "conditions": ["won", "prize", "aadhaar"],
        "reason": "Lottery scam asking for Aadhaar details to 'claim prize'",
        "weight": 80
    },
    {
        "conditions": ["collect request", "accept", "kyc"],
        "reason": "Fake collect request disguised as KYC — never accept unknown collect requests",
        "weight": 88
    },
]

# ── Safe sender indicators (reduce false positives) ──────────────────────
# If these are present, lower the score — these suggest legitimate messages
SAFE_INDICATORS = [
    "do not share", "never share", "do not give",
    "we will never ask", "bank will never ask",
    "otp is valid for", "transaction id",
    "your otp is", "this is an automated message"
]


# ══════════════════════════════════════════════════════════════════════════
# MAIN DETECTION FUNCTION
# ══════════════════════════════════════════════════════════════════════════

def analyze_text(text: str) -> dict:
    """
    Run all rule-based checks on input text.

    Returns:
        {
            "score": 0-100,
            "reasons": ["reason1", "reason2", ...],
            "matched_categories": ["KYC", "OTP", ...],
            "has_suspicious_url": True/False,
            "extracted_urls": [...],
            "urgency_detected": True/False
        }
    """
    if not text or not text.strip():
        return _empty_result()

    cleaned = clean_text(text)
    raw_score = 0
    reasons = []
    matched_categories = []

    # ── 1. Check each keyword pattern group ───────────────────────────────
    pattern_groups = [
        ("KYC Scam",              KYC_PATTERNS),
        ("OTP Fraud",             OTP_PATTERNS),
        ("Account Block Scam",    ACCOUNT_BLOCK_PATTERNS),
        ("Fake Refund",           REFUND_PATTERNS),
        ("UPI PIN Harvest",       UPI_PIN_PATTERNS),
        ("Reward/Prize Scam",     REWARD_PATTERNS),
        ("Support Impersonation", SUPPORT_IMPERSONATION),
        ("Credential Harvesting", CREDENTIAL_PATTERNS),
        ("Identity Harvesting",   IDENTITY_PATTERNS),
        ("Advance Fee Fraud",     ADVANCE_FEE_PATTERNS),
        ("Phishing Link",         PHISHING_LINK_PATTERNS),
    ]

    for category_name, pattern in pattern_groups:
        matched = contains_any(cleaned, pattern["keywords"])
        if matched:
            raw_score += pattern["weight"]
            reasons.append(pattern["reason"])
            matched_categories.append(category_name)

    # ── 2. Check combination rules (highest confidence) ───────────────────
    for combo in COMBINATION_RULES:
        if contains_all(cleaned, combo["conditions"]):
            raw_score += combo["weight"]
            reasons.append(combo["reason"])
            matched_categories.append("High-Confidence Combination")

    # ── 3. Check for suspicious TLDs in message ───────────────────────────
    has_suspicious_url = False
    if SUSPICIOUS_TLD_REGEX.search(cleaned):
        raw_score += 50
        reasons.append("Contains link with suspicious domain extension (.xyz, .info, .online, etc.)")
        has_suspicious_url = True
        matched_categories.append("Suspicious URL")

    # ── 4. Check for IP address URLs ──────────────────────────────────────
    if IP_URL_REGEX.search(cleaned):
        raw_score += 60
        reasons.append("Contains IP address as URL host — legitimate services use domain names")
        has_suspicious_url = True
        matched_categories.append("IP Address URL")

    # ── 5. Urgency check ──────────────────────────────────────────────────
    urgency = has_urgency_indicators(cleaned)
    if urgency and raw_score > 0:
        # Only boost if other signals already present — urgency alone is not enough
        raw_score += 15
        reasons.append("Uses urgency/pressure language to force immediate action")

    # ── 6. Safe indicator check (reduce false positives) ──────────────────
    safe_matches = contains_any(cleaned, SAFE_INDICATORS)
    if safe_matches:
        # Legitimate OTP messages often say "do not share this OTP"
        raw_score = max(0, raw_score - 40)
        if raw_score < 20:
            reasons = []  # Clear reasons if score dropped very low
            matched_categories = []

    # ── 7. Normalize score to 0-100 ───────────────────────────────────────
    # Raw score can exceed 100 if multiple patterns fire — cap it
    final_score = min(100, raw_score)

    # Extract URLs from original text for further analysis
    extracted_urls = extract_urls(text)

    return {
        "score": final_score,
        "reasons": list(dict.fromkeys(reasons)),  # deduplicate, preserve order
        "matched_categories": list(set(matched_categories)),
        "has_suspicious_url": has_suspicious_url,
        "extracted_urls": extracted_urls,
        "urgency_detected": urgency
    }


def _empty_result() -> dict:
    return {
        "score": 0,
        "reasons": [],
        "matched_categories": [],
        "has_suspicious_url": False,
        "extracted_urls": [],
        "urgency_detected": False
    }
