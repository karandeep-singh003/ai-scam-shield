"""
Unified Risk Scoring Engine
=============================
Combines scores from all four engines into one final verdict.
This is the brain that produces the final API response.
"""

from app.config import THREAT_LEVELS, SCAM_THRESHOLD


def calculate_risk(
    rule_result: dict,
    ml_result:   dict,
    url_result:  dict,
    upi_result:  dict,
    input_type:  str = "text"  # "text", "url", or "upi"
) -> dict:
    """
    Combine engine scores into final risk assessment.

    IMPORTANT FIX:
    - For text input, URL score should ONLY contribute if a REAL URL was present.
    - This prevents false positives where plain text gets misinterpreted as a URL.
    """

    # ── Detect whether URL engine analyzed a real URL ─────────────────────
    url_present = bool(url_result.get("url_present", False))

    # ── Pick weights based on input type ──────────────────────────────────
    if input_type == "url":
        weights = {"rule": 0.20, "ml": 0.20, "url": 0.60, "upi": 0.00}

    elif input_type == "upi":
        weights = {"rule": 0.30, "ml": 0.20, "url": 0.00, "upi": 0.50}

    else:  # default: text
        # If there is NO actual URL in the text, URL weight must be 0
        if url_present:
            weights = {"rule": 0.35, "ml": 0.35, "url": 0.15, "upi": 0.15}
        else:
            # Redistribute URL weight into rule + ML + UPI
            weights = {"rule": 0.42, "ml": 0.42, "url": 0.00, "upi": 0.16}

    # ── Extract scores from each engine ───────────────────────────────────
    rule_score = rule_result.get("score", 0)
    ml_score   = ml_result.get("score",   0)
    url_score  = url_result.get("score",  0) if url_present else 0
    upi_score  = upi_result.get("score",  0)

    # ── Weighted combination ───────────────────────────────────────────────
    raw_combined = (
        rule_score * weights["rule"] +
        ml_score   * weights["ml"]   +
        url_score  * weights["url"]  +
        upi_score  * weights["upi"]
    )

    # ── Override: if any engine is extremely confident, boost final score ─
    # NOTE: only use URL score here if a real URL was actually present
    max_individual = max(rule_score, ml_score, (url_score if url_present else 0), upi_score)

    if max_individual >= 90:
        # Any engine at 90+ → final score gets a floor of 70
        final_score = max(raw_combined, 70.0)
    elif max_individual >= 75:
        final_score = max(raw_combined, 55.0)
    else:
        final_score = raw_combined

    final_score = round(min(100.0, max(0.0, final_score)))

    # ── Trusted URL override ──────────────────────────────────────────────
    # Only apply if a REAL URL was analyzed
    if url_present and url_result.get("is_trusted", False):
        final_score = min(final_score, 10)

    # ── Determine threat level ─────────────────────────────────────────────
    threat_level = _get_threat_level(final_score)

    # ── Collect all reasons ────────────────────────────────────────────────
    all_reasons = []
    all_reasons.extend(rule_result.get("reasons", []))
    all_reasons.extend(ml_result.get("reasons",   []))

    if url_present:
        all_reasons.extend(url_result.get("reasons", []))

    all_reasons.extend(upi_result.get("reasons", []))

    # Deduplicate while preserving order
    seen = set()
    unique_reasons = []
    for r in all_reasons:
        if r not in seen:
            seen.add(r)
            unique_reasons.append(r)

    # ── Determine primary category ────────────────────────────────────────
    category = _determine_category(
        rule_result, ml_result, url_result, upi_result, final_score
    )

    # ── Generate advice ────────────────────────────────────────────────────
    advice = _generate_advice(
        threat_level, category, upi_result, url_result
    )

    # ── Build score breakdown (useful for debugging/demo) ─────────────────
    score_breakdown = {
        "rule_engine": rule_score,
        "ml_engine":   ml_score,
        "url_engine":  url_score if url_present else 0,
        "upi_engine":  upi_score,
        "weights_used": weights,
        "url_present": url_present,
    }

    return {
        "is_scam":         final_score >= SCAM_THRESHOLD,
        "risk_score":      final_score,
        "threat_level":    threat_level,
        "category":        category,
        "reasons":         unique_reasons,
        "advice":          advice,
        "score_breakdown": score_breakdown,
        "ml_probability":  ml_result.get("probability", 0.0),
    }


def _get_threat_level(score: float) -> str:
    """
    THREAT_LEVELS is expected like:
    {
        "Critical": 85,
        "High": 65,
        "Medium": 35,
        "Low": 0
    }
    """
    for level, threshold in THREAT_LEVELS.items():
        if score >= threshold:
            return level
    return "Low"


def _determine_category(rule_r, ml_r, url_r, upi_r, score) -> str:
    """Pick the most specific category from matched engines."""

    # UPI engine category takes priority if strongly triggered
    if upi_r.get("score", 0) >= 50:
        return upi_r.get("category", "UPI Fraud")

    # URL engine category only if a REAL URL was analyzed
    if url_r.get("url_present", False) and url_r.get("score", 0) >= 50:
        return "Phishing URL"

    # Rule engine categories
    rule_cats = rule_r.get("matched_categories", [])
    if rule_cats:
        priority = [
            "UPI PIN Harvest", "OTP Fraud", "Credential Harvesting",
            "High-Confidence Combination", "KYC Scam", "Fake Refund",
            "Advance Fee Fraud", "Reward/Prize Scam",
            "Account Block Scam", "Phishing Link"
        ]
        for cat in priority:
            if cat in rule_cats:
                return cat
        return rule_cats[0]

    # ML fallback
    if ml_r.get("score", 0) >= 55:
        return "ML-Detected Scam Pattern"

    if score < 25:
        return "Likely Legitimate"

    return "Suspicious Content"


def _generate_advice(threat_level, category, upi_r, url_r) -> str:
    """Generate actionable advice based on threat level and category."""

    # Use UPI engine's specific advice if available
    upi_advice = upi_r.get("advice", "")
    if upi_advice and upi_r.get("score", 0) >= 50:
        return upi_advice

    advice_map = {
        "Critical": (
            "Do NOT proceed. This is almost certainly a scam. "
            "Do not click any links, share any details, or make any payments. "
            "Block the sender and report to cybercrime.gov.in or call 1930."
        ),
        "High": (
            "Treat this with extreme caution. Do not share any personal, "
            "banking, or UPI details. Verify through the official app or "
            "website of the organisation mentioned."
        ),
        "Medium": (
            "Be cautious. Do not click links in this message. "
            "If you need to verify your account, go directly to the "
            "official app or website — never through links in messages."
        ),
        "Low": (
            "This appears to be mostly safe, but always stay alert. "
            "Never share OTP, UPI PIN, or banking passwords with anyone."
        ),
    }

    # URL-specific advice only if a REAL URL was analyzed
    if url_r.get("url_present", False) and url_r.get("score", 0) >= 50:
        return (
            "Do not visit this URL. It shows multiple signs of being a "
            "phishing website. Legitimate organisations do not send "
            "links to unrecognised domains. Report at cybercrime.gov.in."
        )

    return advice_map.get(threat_level, advice_map["Low"])
