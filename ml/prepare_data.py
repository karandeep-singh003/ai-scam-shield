"""
Data preparation script.
Run this once before training.
It merges seed data + public datasets into clean train/test CSVs.
"""

import pandas as pd
import os
import re
from sklearn.model_selection import train_test_split

# ── Paths ──────────────────────────────────────────────────────────────────
SEED_SMS   = "data/seed/sms_seed.csv"
SEED_URL   = "data/seed/url_seed.csv"
SEED_UPI   = "data/seed/upi_seed.csv"
RAW_KAGGLE_SMS = "data/raw/spam.csv"          # Kaggle SMS spam dataset
OUT_TEXT   = "data/processed/text_dataset.csv"
OUT_URL    = "data/processed/url_dataset.csv"
OUT_UPI    = "data/processed/upi_dataset.csv"

os.makedirs("data/processed", exist_ok=True)


# ── Text cleaner ───────────────────────────────────────────────────────────
def clean_text(text: str) -> str:
    """
    Light cleaning only — we keep scam-relevant words like 'OTP', 'PIN', 'KYC'.
    Over-cleaning removes the very signals we need to detect.
    """
    if not isinstance(text, str):
        return ""
    text = text.lower().strip()
    # Remove extra whitespace
    text = re.sub(r'\s+', ' ', text)
    # Remove special characters but keep numbers (amounts like Rs 500 matter)
    text = re.sub(r'[^\w\s₹]', ' ', text)
    return text.strip()


# ── Build text dataset ─────────────────────────────────────────────────────
def build_text_dataset():
    frames = []

    # 1. Load our seed data (always present)
    seed = pd.read_csv(SEED_SMS)
    seed = seed[['text', 'label']].dropna()
    seed['text'] = seed['text'].apply(clean_text)
    seed['source'] = 'seed'
    frames.append(seed)
    print(f"Seed SMS rows loaded: {len(seed)}")

    # 2. Load Kaggle SMS spam dataset if present
    if os.path.exists(RAW_KAGGLE_SMS):
        try:
            # Kaggle file has columns: v1 (ham/spam), v2 (text)
            kaggle = pd.read_csv(RAW_KAGGLE_SMS, encoding='latin-1',
                                 usecols=['v1', 'v2'])
            kaggle.columns = ['label_text', 'text']
            kaggle['label'] = kaggle['label_text'].map({'spam': 1, 'ham': 0})
            kaggle = kaggle[['text', 'label']].dropna()
            kaggle['text'] = kaggle['text'].apply(clean_text)
            kaggle['source'] = 'kaggle'
            frames.append(kaggle)
            print(f"Kaggle SMS rows loaded: {len(kaggle)}")
        except Exception as e:
            print(f"Could not load Kaggle SMS data: {e}")
    else:
        print("Kaggle SMS file not found — using seed data only. That's fine for now.")

    # 3. Merge all sources
    df = pd.concat(frames, ignore_index=True)
    df = df.drop_duplicates(subset='text')

    # 4. Show class balance
    print(f"\nText dataset class balance:")
    print(df['label'].value_counts())
    print(f"Total rows: {len(df)}")

    # 5. Train / validation / test split  (70% / 15% / 15%)
    train, temp = train_test_split(df, test_size=0.30,
                                   random_state=42, stratify=df['label'])
    val, test   = train_test_split(temp, test_size=0.50,
                                   random_state=42, stratify=temp['label'])

    train.to_csv("data/processed/text_train.csv", index=False)
    val.to_csv("data/processed/text_val.csv",     index=False)
    test.to_csv("data/processed/text_test.csv",   index=False)
    df.to_csv(OUT_TEXT, index=False)

    print(f"\nSplit → Train: {len(train)}  Val: {len(val)}  Test: {len(test)}")
    print(f"Saved to data/processed/")


# ── Build URL dataset ──────────────────────────────────────────────────────
def build_url_dataset():
    seed = pd.read_csv(SEED_URL)
    seed = seed[['url', 'label']].dropna()
    seed['source'] = 'seed'

    print(f"\nURL dataset class balance:")
    print(seed['label'].value_counts())
    print(f"Total URL rows: {len(seed)}")

    seed.to_csv(OUT_URL, index=False)
    print(f"Saved to {OUT_URL}")

    # Note: URL engine uses heuristics, not ML training
    # So we don't need a large URL training set right now


# ── Build UPI dataset ──────────────────────────────────────────────────────
def build_upi_dataset():
    seed = pd.read_csv(SEED_UPI)
    seed = seed[['text', 'label', 'category']].dropna()
    seed['text'] = seed['text'].apply(clean_text)
    seed['source'] = 'seed'

    print(f"\nUPI dataset class balance:")
    print(seed['label'].value_counts())
    print(f"Total UPI rows: {len(seed)}")

    seed.to_csv(OUT_UPI, index=False)
    print(f"Saved to {OUT_UPI}")


# ── Run all ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 50)
    print("Building text dataset...")
    print("=" * 50)
    build_text_dataset()

    print("\n" + "=" * 50)
    print("Building URL dataset...")
    print("=" * 50)
    build_url_dataset()

    print("\n" + "=" * 50)
    print("Building UPI dataset...")
    print("=" * 50)
    build_upi_dataset()

    print("\n✅ All datasets prepared successfully.")
    print("Next step: run  python3 ml/train.py")
