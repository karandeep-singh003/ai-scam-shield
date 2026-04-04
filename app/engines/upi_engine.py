"""
UPI Fraud Detection Engine
============================
India-specific UPI scam detection.
This is what makes AI Scam Shield unique — no public English
dataset captures these patterns. This is hand-crafted domain knowledge.

KEY INSIGHT:
In UPI, you NEVER need to enter your PIN to RECEIVE money.
PIN is only needed to SEND money.
Any message asking for PIN to receive = 100% scam.
"""

from app.utils.text_cleaner import (
    clean_text, contains_any, contains_all
)


# ══════════════════════════════════════════════════════════════════════════
# UPI FRAUD PATTERN LIBRARY
# ══════════════════════════════════════════════════════════════════════════

# ── Category 1: PIN harvest (most dangerous) ──────────────────────────────
PIN_HARVEST_PATTERNS = {
    "keywords": [
        "enter upi pin", "enter your upi pin", "enter pin to receive",
        "enter pin to accept", "enter pin to get refund",
        "share upi pin", "provide upi pin", "send upi pin",
        "upi pin to receive", "pin to receive money",
        "enter mpin", "enter your mpin to receive",
    ],
    "contradictions": [
        # These word pairs prove it's a scam — PIN + receive is always fraud
        (["pin", "receive"], "You never need a PIN to receive money on UPI"),
        (["pin", "refund"],  "You never need a PIN to receive a refund"),
        (["pin", "cashback"],"You never need a PIN to receive cashback"),
        (["pin", "prize"],   "You never need a PIN to claim a prize"),
        (["pin", "credit"],  "You never need a PIN for money to be credited"),
    ],
    "category": "UPI PIN Harvest",
    "weight": 95,
    "advice": (
        "NEVER enter your UPI PIN to receive money. "
        "UPI PIN is only required when YOU are sending money. "
        "This is a PIN harvest scam — block and report this contact immediately."
    )
}

# ── Category 2: Collect request fraud ────────────────────────────────────
COLLECT_REQUEST_PATTERNS = {
    "keywords": [
        "collect request", "payment request", "accept request",
        "approve request", "pending request", "incoming request",
        "accept to receive", "approve to receive",
        "collect from", "accept collect",
    ],
    "suspicious_combos": [
        ["collect request", "kyc"],
        ["collect request", "bank"],
        ["collect request", "refund"],
        ["accept", "request", "receive money"],
        ["approve", "request", "credited"],
    ],
    "category": "Collect Request Fraud",
    "weight": 80,
    "advice": (
        "A collect request means YOU will be CHARGED, not paid. "
        "Scammers send collect requests disguised as refunds or prizes. "
        "Never accept collect requests from unknown contacts."
    )
}

# ── Category 3: Fake refund scam ──────────────────────────────────────────
FAKE_REFUND_PATTERNS = {
    "keywords": [
        "upi refund", "refund to your upi", "refund via upi",
        "process your refund", "initiate refund",
        "refund credited", "refund pending upi",
        "enter details for refund", "share upi for refund",
    ],
    "category": "Fake UPI Refund",
    "weight": 65,
    "advice": (
        "Legitimate refunds are processed automatically to your original "
        "payment method. You never need to 'verify' or 'enter PIN' "
        "to receive a refund. This is a fake refund scam."
    )
}

# ── Category 4: QR code scam ──────────────────────────────────────────────
QR_SCAM_PATTERNS = {
    "keywords": [
        "scan qr", "scan this qr", "scan qr code to receive",
        "scan and receive", "qr code for payment",
        "scan to get money", "qr to claim",
        "send qr", "share qr code",
    ],
    "contradiction_combos": [
        # Scanning a QR to RECEIVE money is fraud — QR codes deduct money
        ["scan", "qr", "receive"],
        ["scan", "qr", "refund"],
        ["scan", "qr", "prize"],
        ["scan", "qr", "cashback"],
    ],
    "category": "QR Code Scam",
    "weight": 75,
    "advice": (
        "Scanning a QR code on UPI SENDS money — it never receives money. "
        "If someone asks you to scan a QR code to receive a prize or refund, "
        "that is a scam. You will lose money, not gain it."
    )
}

# ── Category 5: Fake cashback/reward ─────────────────────────────────────
CASHBACK_SCAM_PATTERNS = {
    "keywords": [
        "upi cashback", "gpay cashback", "phonepe cashback",
        "paytm cashback offer", "upi reward", "upi bonus",
        "enter upi to claim", "share upi id to receive cashback",
        "upi lucky winner", "bhim cashback",
    ],
    "category": "Fake UPI Cashback/Reward",
    "weight": 60,
    "advice": (
        "Legitimate cashback is credited automatically — "
        "no action is ever required from you. "
        "Never share your UPI ID or PIN for cashback claims."
    )
}

# ── Category 6: KYC + UPI combination ────────────────────────────────────
KYC_UPI_PATTERNS = {
    "keywords": [
        "upi kyc", "phonepe kyc", "paytm kyc update",
        "gpay kyc", "bhim kyc", "upi id blocked",
        "upi limit exceeded kyc", "complete kyc to use upi",
        "upi suspended kyc",
    ],
    "category": "UPI KYC Fraud",
    "weight": 70,
    "advice": (
        "KYC for UPI apps is done through the official app only — "
        "never through a link sent via SMS or WhatsApp. "
        "Contact your bank's official customer care if there is a real issue."
    )
}

# ── Category 7: Fake support impersonation ───────────────────────────────
FAKE_SUPPORT_PATTERNS = {
    "keywords": [
        "phonepe support", "paytm helpline", "gpay customer care",
        "upi helpdesk", "bhim support team",
        "call our upi executive", "upi fraud team",
        "rbi upi team", "npci helpline",
    ],
    "category": "UPI Support Impersonation",
    "weight": 55,
    "advice": (
        "NPCI, RBI, PhonePe, and Paytm never contact you via SMS or WhatsApp "
        "to resolve UPI issues. Official support is only through the app. "
        "This is an impersonation scam."
    )
}

# ── Advice for unknown UPI scams ─────────────────────────────────────────
DEFAULT_ADVICE = (
    "Be cautious with this UPI-related message. "
    "Never share your UPI PIN, OTP, or banking details with anyone. "
    "When in doubt, contact your bank through the official app or website."
)


# ══════════════════════════════════════════════════════════════════════════
# MAIN ANALYSIS FUNCTION
# ══════════════════════════════════════════════════════════════════════════

def analyze_upi(text: str) -> dict:
    """
    Analyze text for UPI-specific fraud patterns.

    Returns:
        {
            "score": 0-100,
            "category": "UPI PIN Harvest" / "Collect Request Fraud" / etc,
            "reasons": [...],
            "advice": "What the user should do",
            "is_upi_related": True/False
        }
    """
    if not text or not text.strip():
        return _empty_result()

    cleaned = clean_text(text).lower()
    raw_score = 0
    reasons   = []
    categories_matched = []
    advice    = DEFAULT_ADVICE

    # ── Check 1: PIN harvest ───────────────────────────────────────────────
    if contains_any(cleaned, PIN_HARVEST_PATTERNS["keywords"]):
        raw_score += PIN_HARVEST_PATTERNS["weight"]
        reasons.append("Asks for UPI PIN — you NEVER need PIN to receive money")
        categories_matched.append(PIN_HARVEST_PATTERNS["category"])
        advice = PIN_HARVEST_PATTERNS["advice"]

    # Check PIN contradiction combos
    for combo, reason in PIN_HARVEST_PATTERNS["contradictions"]:
        if contains_all(cleaned, combo):
            raw_score += 95
            reasons.append(reason)
            if PIN_HARVEST_PATTERNS["category"] not in categories_matched:
                categories_matched.append(PIN_HARVEST_PATTERNS["category"])
            advice = PIN_HARVEST_PATTERNS["advice"]
            break

    # ── Check 2: Collect request fraud ────────────────────────────────────
    if contains_any(cleaned, COLLECT_REQUEST_PATTERNS["keywords"]):
        raw_score += COLLECT_REQUEST_PATTERNS["weight"]
        reasons.append(
            "Contains collect request language — "
            "collect requests DEDUCT money, not add it"
        )
        categories_matched.append(COLLECT_REQUEST_PATTERNS["category"])
        if not advice or advice == DEFAULT_ADVICE:
            advice = COLLECT_REQUEST_PATTERNS["advice"]

    for combo in COLLECT_REQUEST_PATTERNS["suspicious_combos"]:
        if contains_all(cleaned, combo):
            raw_score += 85
            reasons.append(
                f"Collect request combined with suspicious context: "
                f"{' + '.join(combo)}"
            )
            break

    # ── Check 3: Fake refund ───────────────────────────────────────────────
    if contains_any(cleaned, FAKE_REFUND_PATTERNS["keywords"]):
        raw_score += FAKE_REFUND_PATTERNS["weight"]
        reasons.append("Fake UPI refund claim — legitimate refunds are automatic")
        categories_matched.append(FAKE_REFUND_PATTERNS["category"])
        if advice == DEFAULT_ADVICE:
            advice = FAKE_REFUND_PATTERNS["advice"]

    # ── Check 4: QR scam ──────────────────────────────────────────────────
    if contains_any(cleaned, QR_SCAM_PATTERNS["keywords"]):
        raw_score += QR_SCAM_PATTERNS["weight"]
        reasons.append("QR code scam — scanning QR sends money, never receives it")
        categories_matched.append(QR_SCAM_PATTERNS["category"])
        if advice == DEFAULT_ADVICE:
            advice = QR_SCAM_PATTERNS["advice"]

    for combo in QR_SCAM_PATTERNS["contradiction_combos"]:
        if contains_all(cleaned, combo):
            raw_score += 80
            reasons.append(
                "QR code presented as a way to RECEIVE money — "
                "this is always fraud"
            )
            break

    # ── Check 5: Fake cashback ────────────────────────────────────────────
    if contains_any(cleaned, CASHBACK_SCAM_PATTERNS["keywords"]):
        raw_score += CASHBACK_SCAM_PATTERNS["weight"]
        reasons.append("Fake UPI cashback or reward claim")
        categories_matched.append(CASHBACK_SCAM_PATTERNS["category"])

    # ── Check 6: KYC + UPI ────────────────────────────────────────────────
    if contains_any(cleaned, KYC_UPI_PATTERNS["keywords"]):
        raw_score += KYC_UPI_PATTERNS["weight"]
        reasons.append("UPI KYC fraud — KYC is done in-app only, never via SMS")
        categories_matched.append(KYC_UPI_PATTERNS["category"])
        if advice == DEFAULT_ADVICE:
            advice = KYC_UPI_PATTERNS["advice"]

    # ── Check 7: Fake support ─────────────────────────────────────────────
    if contains_any(cleaned, FAKE_SUPPORT_PATTERNS["keywords"]):
        raw_score += FAKE_SUPPORT_PATTERNS["weight"]
        reasons.append("Impersonates UPI platform support team")
        categories_matched.append(FAKE_SUPPORT_PATTERNS["category"])

    # ── Is this even UPI-related? ─────────────────────────────────────────
    upi_general_terms = [
        "upi", "phonepe", "gpay", "google pay", "paytm",
        "bhim", "npci", "upi id", "@paytm", "@oksbi",
        "@okhdfcbank", "@okaxis", "@ybl", "@apl"
    ]
    is_upi_related = len(contains_any(cleaned, upi_general_terms)) > 0

    # ── Final score ────────────────────────────────────────────────────────
    final_score  = min(100, raw_score)
    top_category = categories_matched[0] if categories_matched else (
        "UPI Related" if is_upi_related else "Not UPI Related"
    )

    return {
        "score":          final_score,
        "category":       top_category,
        "reasons":        list(dict.fromkeys(reasons)),
        "advice":         advice if final_score > 20 else "",
        "is_upi_related": is_upi_related
    }


def _empty_result() -> dict:
    return {
        "score": 0,
        "category": "Not UPI Related",
        "reasons": [],
        "advice": "",
        "is_upi_related": False
    }
