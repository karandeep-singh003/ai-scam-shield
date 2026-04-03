"""
Tests for the rule-based detection engine.
Run with: pytest tests/test_rule_engine.py -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.engines.rule_engine import analyze_text


# ── High-confidence scam inputs ───────────────────────────────────────────
def test_upi_pin_harvest():
    result = analyze_text("Enter your UPI PIN to receive Rs 500 cashback")
    assert result["score"] >= 70, f"Expected score >= 70, got {result['score']}"
    assert len(result["reasons"]) > 0

def test_otp_sharing_scam():
    result = analyze_text("Share the OTP with our bank executive to complete KYC")
    assert result["score"] >= 60

def test_kyc_urgency_scam():
    result = analyze_text("Your SBI account is blocked. Complete KYC immediately at http://sbi-kyc.xyz")
    assert result["score"] >= 60
    assert result["has_suspicious_url"] == True

def test_fake_refund():
    result = analyze_text("Income tax refund of Rs 8750 pending. Submit details at incometax-claim.online")
    assert result["score"] >= 40

def test_lottery_scam():
    result = analyze_text("Congratulations you have won Rs 50000 in KBC lucky draw. Share Aadhaar to claim")
    assert result["score"] >= 50

def test_ip_address_url():
    result = analyze_text("Login to your account at http://192.168.1.1/sbi/login")
    assert result["has_suspicious_url"] == True
    assert result["score"] >= 50


# ── Legitimate inputs — should score LOW ──────────────────────────────────
def test_legitimate_otp_message():
    # Real OTP messages say "do not share" — should not be flagged
    result = analyze_text("Your SBI OTP is 482910. Valid for 10 minutes. Do not share with anyone.")
    assert result["score"] < 30, f"Legitimate OTP scored too high: {result['score']}"

def test_legitimate_transaction():
    result = analyze_text("Your UPI transaction of Rs 500 to Swiggy is successful. Transaction ID: UPI20240315")
    assert result["score"] < 20

def test_legitimate_bank_statement():
    result = analyze_text("Your HDFC bank statement for March is ready. Login to net banking to view.")
    assert result["score"] < 25

def test_empty_input():
    result = analyze_text("")
    assert result["score"] == 0
    assert result["reasons"] == []


# ── Quick manual test ─────────────────────────────────────────────────────
if __name__ == "__main__":
    test_cases = [
        ("SCAM", "Dear customer enter your UPI PIN to receive Rs 500 refund from Paytm"),
        ("SCAM", "Your HDFC account blocked. Update KYC at http://hdfc-kyc.xyz immediately"),
        ("SCAM", "Congratulations you won Rs 25000! Share Aadhaar number to claim prize"),
        ("LEGIT", "Your OTP is 291847. Valid for 10 minutes. Do not share with anyone."),
        ("LEGIT", "Your Swiggy order will arrive in 20 minutes. Track: swiggy.com/orders"),
        ("LEGIT", "HDFC: Rs 1500 debited from account XX1234 for Amazon order. Not you? Call 1800-XXX"),
    ]

    print("\n" + "=" * 60)
    print("RULE ENGINE — MANUAL TEST")
    print("=" * 60)

    for expected, text in test_cases:
        result = analyze_text(text)
        score = result["score"]
        verdict = "SCAM" if score >= 40 else "SAFE"
        match = "✅" if verdict == expected else "❌"
        print(f"\n{match} [{expected}] Score: {score}")
        print(f"   Text: {text[:65]}...")
        if result["reasons"]:
            print(f"   Reason: {result['reasons'][0]}")
