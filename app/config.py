"""
Central configuration for AI Scam Shield.
All weights, thresholds, and score mappings live here.
Change these values to tune detection sensitivity.
"""

# ── Score weights (must sum to 1.0) ────────────────────────────────────────
# How much each engine contributes to the final risk score
WEIGHTS = {
    "rule":  0.35,   # Rule engine — high precision, catches obvious scams
    "ml":    0.35,   # ML engine   — catches subtle patterns
    "url":   0.15,   # URL engine  — only relevant when URL is present
    "upi":   0.15,   # UPI engine  — India-specific fraud patterns
}

# ── Threat level thresholds ────────────────────────────────────────────────
# Final score → threat level mapping
THREAT_LEVELS = {
    "Critical": 75,   # score >= 75 → Critical
    "High":     50,   # score >= 50 → High
    "Medium":   25,   # score >= 25 → Medium
    "Low":       0,   # score >= 0  → Low
}

# ── is_scam threshold ──────────────────────────────────────────────────────
# Final score above this → is_scam = True
SCAM_THRESHOLD = 40

# ── ML probability threshold ───────────────────────────────────────────────
# ML model raw probability above this = treat as scam signal
ML_SCAM_PROBABILITY_THRESHOLD = 0.55

# ── Rule engine max score ──────────────────────────────────────────────────
# Raw rule scores are capped at this before weighting
RULE_MAX_SCORE = 100

# ── URL engine max score ───────────────────────────────────────────────────
URL_MAX_SCORE = 100

# ── App metadata ───────────────────────────────────────────────────────────
APP_TITLE       = "AI Scam Shield"
APP_VERSION     = "1.0.0"
APP_DESCRIPTION = "AI-powered detection for phishing, SMS scams, and UPI fraud"
# CI verified Mon Apr 27 00:49:36 IST 2026
# CI pipeline verified Mon Apr 27 03:14:32 IST 2026
