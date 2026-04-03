"""
Generates India-specific synthetic scam and legitimate SMS examples.
Run this to boost dataset size before training.
Output is appended to data/seed/sms_seed.csv
"""

import csv
import random
import os

# ── Scam templates ─────────────────────────────────────────────────────────
SCAM_TEMPLATES = [
    "Dear {bank} customer your account is blocked. Update KYC at {url} immediately",
    "Your {bank} account will be suspended in {hours} hours. Call {phone} now",
    "Congratulations! You won Rs {amount} in {lottery}. Share Aadhaar to claim",
    "URGENT: Your PAN card linked to {bank} needs verification. Click {url}",
    "Your {wallet} wallet KYC is pending. Complete at {url} or wallet will be blocked",
    "Income Tax refund of Rs {amount} is pending. Submit details at {url}",
    "Dear customer enter UPI PIN to receive Rs {amount} cashback from {wallet}",
    "Your electricity bill is overdue. Pay Rs {amount} now to avoid disconnection at {phone}",
    "OTP for {bank} transaction is {otp}. Share with our executive to complete KYC",
    "FREE: {wallet} selected your number for Rs {amount} reward. Send PIN to claim",
    "Your {bank} credit card ending {card} is blocked. Verify at {url}",
    "ALERT: Suspicious transaction on your {wallet}. Call {phone} immediately",
    "Dear user {wallet} is updating KYC. Enter OTP {otp} sent to complete verification",
    "You have a collect request of Rs {amount} from {bank} refund team. Accept now",
    "Scan QR code to receive Rs {amount} prize from {lottery} lucky draw",
]

LEGIT_TEMPLATES = [
    "Your {bank} account balance is Rs {amount}. Transaction on {date}",
    "OTP for your {bank} login is {otp}. Valid for 10 minutes. Do not share",
    "Your {wallet} transaction of Rs {amount} to {merchant} is successful",
    "Dear customer your FD of Rs {amount} matures on {date}. Visit branch to renew",
    "Your IRCTC ticket PNR {pnr} for {date} is confirmed",
    "Hi your {bank} credit card bill of Rs {amount} is due on {date}",
    "Your {wallet} KYC is complete. You can now send up to Rs 1 lakh per month",
    "Transaction alert: Rs {amount} debited from {bank} account for {merchant} payment",
    "Your SIP of Rs {amount} in {fund} has been processed for {date}",
    "Reminder: {bank} EMI of Rs {amount} due on {date}. Maintain sufficient balance",
]

# ── Fill-in values ─────────────────────────────────────────────────────────
BANKS   = ["SBI", "HDFC", "ICICI", "Axis", "Kotak", "PNB", "Bank of Baroda"]
WALLETS = ["Paytm", "PhonePe", "Google Pay", "BHIM", "Amazon Pay"]
URLS    = ["http://sbi-kyc.xyz", "http://hdfc-verify.net", "http://paytm-update.info",
           "http://incometax-claim.online", "http://yono-update.xyz"]
PHONES  = ["9876543210", "8765432109", "7654321098", "1800-XXX-XXXX"]
LOTTERY = ["KBC", "Jio Lucky Draw", "Amazon Great Sale", "Flipkart Spin & Win"]
MERCHANTS = ["Swiggy", "Zomato", "Amazon", "Flipkart", "BigBasket", "Jio", "Airtel"]
FUNDS   = ["SBI Bluechip Fund", "HDFC Top 100", "Axis Long Term Equity"]
DATES   = ["15 April", "1 May", "20 March", "5 April", "30 April"]

def fill(template):
    return template.format(
        bank    = random.choice(BANKS),
        wallet  = random.choice(WALLETS),
        url     = random.choice(URLS),
        phone   = random.choice(PHONES),
        lottery = random.choice(LOTTERY),
        merchant= random.choice(MERCHANTS),
        fund    = random.choice(FUNDS),
        date    = random.choice(DATES),
        amount  = random.choice([500, 1000, 2500, 5000, 10000, 25000, 50000]),
        hours   = random.choice([2, 4, 12, 24]),
        otp     = random.randint(100000, 999999),
        card    = random.randint(1000, 9999),
        pnr     = random.randint(1000000000, 9999999999),
    )


def generate(n_scam=100, n_legit=100):
    rows = []
    for _ in range(n_scam):
        text = fill(random.choice(SCAM_TEMPLATES))
        rows.append({'text': text, 'label': 1})
    for _ in range(n_legit):
        text = fill(random.choice(LEGIT_TEMPLATES))
        rows.append({'text': text, 'label': 0})
    return rows


if __name__ == "__main__":
    rows = generate(n_scam=100, n_legit=100)

    out_path = "data/seed/sms_seed.csv"
    file_exists = os.path.exists(out_path)

    with open(out_path, 'a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['text', 'label'])
        if not file_exists:
            writer.writeheader()
        writer.writerows(rows)

    print(f"✅ Generated {len(rows)} synthetic examples.")
    print(f"   Appended to {out_path}")
    print(f"   Next: run python3 ml/prepare_data.py")
