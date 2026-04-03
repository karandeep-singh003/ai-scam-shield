"""
Shared text preprocessing utilities.
Used by rule engine, ML engine, and UPI engine.

WHY LIGHT CLEANING ONLY:
Scam detection depends heavily on words like OTP, PIN, KYC, URGENT, FREE.
Over-cleaning (removing stopwords, stemming) destroys these signals.
We only normalize whitespace and lowercase — nothing more aggressive.
"""

import re


# ── Core cleaner ───────────────────────────────────────────────────────────
def clean_text(text: str) -> str:
    """
    Normalize text for detection engines.
    Keeps scam-relevant tokens intact.
    """
    if not isinstance(text, str):
        return ""
    text = text.strip()
    # Collapse multiple spaces/newlines into one space
    text = re.sub(r'\s+', ' ', text)
    return text


def clean_text_for_ml(text: str) -> str:
    """
    Slightly more aggressive cleaning for ML vectorizer only.
    Still keeps numbers (Rs 500 matters) and key scam words.
    """
    if not isinstance(text, str):
        return ""
    text = text.lower().strip()
    text = re.sub(r'\s+', ' ', text)
    # Remove special characters but keep letters, digits, spaces
    text = re.sub(r'[^\w\s]', ' ', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


# ── URL extractor ──────────────────────────────────────────────────────────
def extract_urls(text: str) -> list:
    """
    Pull all URLs out of a text message.
    Returns list of URL strings found.
    """
    url_pattern = re.compile(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|'
        r'(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    )
    return url_pattern.findall(text)


# ── Keyword checker ────────────────────────────────────────────────────────
def contains_any(text: str, keywords: list) -> list:
    """
    Check if text contains any of the given keywords.
    Returns list of matched keywords (empty list = no match).
    Case-insensitive.
    """
    text_lower = text.lower()
    return [kw for kw in keywords if kw.lower() in text_lower]


def contains_all(text: str, keywords: list) -> bool:
    """
    Returns True only if ALL keywords are present in text.
    Used for combination-pattern detection (e.g. 'upi' AND 'pin' AND 'receive').
    """
    text_lower = text.lower()
    return all(kw.lower() in text_lower for kw in keywords)


# ── Amount extractor ───────────────────────────────────────────────────────
def extract_amounts(text: str) -> list:
    """
    Extract rupee amounts mentioned in text.
    Matches: Rs 500, Rs. 1000, ₹500, INR 2500
    Returns list of floats.
    """
    patterns = [
        r'(?:rs\.?|₹|inr)\s*(\d+(?:,\d+)*(?:\.\d+)?)',
    ]
    amounts = []
    for pattern in patterns:
        matches = re.findall(pattern, text.lower())
        for m in matches:
            try:
                amounts.append(float(m.replace(',', '')))
            except ValueError:
                pass
    return amounts


# ── Urgency detector ───────────────────────────────────────────────────────
def has_urgency_indicators(text: str) -> bool:
    """
    Returns True if text has urgency/pressure language.
    Scammers create artificial time pressure.
    """
    urgency_words = [
        'urgent', 'immediately', 'right now', 'within 24 hours',
        'within 2 hours', 'last chance', 'expire', 'suspended',
        'blocked', 'deactivated', 'disconnected', 'tonight',
        'today only', 'limited time', 'act now', 'do not ignore'
    ]
    return len(contains_any(text, urgency_words)) > 0
