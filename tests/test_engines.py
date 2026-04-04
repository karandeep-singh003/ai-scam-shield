"""Quick test of all four engines together."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.engines.rule_engine  import analyze_text as rule_analyze
from app.engines.ml_engine    import load_model, analyze_text as ml_analyze
from app.engines.url_engine   import analyze_url
from app.engines.upi_engine   import analyze_upi
from app.engines.risk_scorer  import calculate_risk

load_model()

test_cases = [
    ("SCAM", "Enter your UPI PIN to receive Rs 500 cashback from PhonePe"),
    ("SCAM", "Your SBI account blocked. Update KYC at http://sbi-kyc.xyz now"),
    ("SCAM", "Scan this QR code to receive your prize money of Rs 25000"),
    ("SCAM", "Congratulations you won Rs 50000 in KBC. Share Aadhaar to claim"),
    ("SAFE", "Your OTP is 291847. Valid 10 mins. Do not share with anyone."),
    ("SAFE", "Your Swiggy order will arrive in 20 minutes"),
    ("SAFE", "HDFC: Rs 1500 debited from account XX1234 for Amazon order"),
]

print("\n" + "=" * 65)
print("ALL ENGINES — END TO END TEST")
print("=" * 65)

all_pass = True
for expected, text in test_cases:
    r = rule_analyze(text)
    m = ml_analyze(text)
    u = analyze_url(text)
    p = analyze_upi(text)
    final = calculate_risk(r, m, u, p)

    verdict = "SCAM" if final["is_scam"] else "SAFE"
    match   = "✅" if verdict == expected else "❌"
    if verdict != expected:
        all_pass = False

    print(f"\n{match} Expected:{expected} Got:{verdict} "
          f"Score:{final['risk_score']} Level:{final['threat_level']}")
    print(f"   Text: {text[:65]}")
    print(f"   Rule:{r['score']} ML:{m['score']} "
          f"UPI:{p['score']} URL:{u['score']}")
    print(f"   Category: {final['category']}")
    if final['reasons']:
        print(f"   Top reason: {final['reasons'][0]}")

print("\n" + "=" * 65)
if all_pass:
    print("✅ ALL TESTS PASSED — engines are working correctly")
else:
    print("⚠️  SOME TESTS FAILED — check scores above")
print("=" * 65)
print("\nNext: python3 app/main.py  (Phase 6 — FastAPI backend)")
