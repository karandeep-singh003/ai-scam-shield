"""
Data preparation script — merges all sources into train/val/test splits.
Run this before training: python3 ml/prepare_data.py
"""

import pandas as pd
import os
import re
from sklearn.model_selection import train_test_split

# ── Paths ──────────────────────────────────────────────────────────────────
SEED_SMS       = "data/seed/sms_seed.csv"
SEED_URL       = "data/seed/url_seed.csv"
SEED_UPI       = "data/seed/upi_seed.csv"
RAW_KAGGLE_SMS = "data/raw/spam.csv"
RAW_ENRON      = "data/raw/enron_spam.csv"
OUT_TEXT       = "data/processed/text_dataset.csv"
OUT_URL        = "data/processed/url_dataset.csv"
OUT_UPI        = "data/processed/upi_dataset.csv"

os.makedirs("data/processed", exist_ok=True)


def clean_text(text):
    if not isinstance(text, str):
        return ""
    text = text.lower().strip()
    text = re.sub(r'\s+', ' ', text)
    text = re.sub(r'[^\w\s]', ' ', text)
    return text.strip()


def build_text_dataset():
    frames = []

    # ── 1. Seed data ───────────────────────────────────────────────────────
    seed = pd.read_csv(SEED_SMS)[['text', 'label']].dropna()
    seed['text'] = seed['text'].apply(clean_text)
    seed['source'] = 'seed'
    frames.append(seed)
    print(f"  Seed SMS rows:   {len(seed)}")

    # ── 2. Kaggle SMS spam ─────────────────────────────────────────────────
    if os.path.exists(RAW_KAGGLE_SMS):
        try:
            kaggle = pd.read_csv(RAW_KAGGLE_SMS, encoding='latin-1',
                                 usecols=['v1', 'v2'])
            kaggle.columns = ['label_text', 'text']
            kaggle['label'] = kaggle['label_text'].map({'spam': 1, 'ham': 0})
            kaggle = kaggle[['text', 'label']].dropna()
            kaggle['text'] = kaggle['text'].apply(clean_text)
            kaggle['source'] = 'kaggle'
            frames.append(kaggle)
            print(f"  Kaggle SMS rows: {len(kaggle)}")
        except Exception as e:
            print(f"  Kaggle SMS skipped: {e}")
    else:
        print("  Kaggle SMS not found — skipping")

    # ── 3. Enron email spam ────────────────────────────────────────────────
    if os.path.exists(RAW_ENRON):
        try:
            enron = pd.read_csv(RAW_ENRON, encoding='latin-1')
            # Enron columns: Spam/Ham, Subject, Message
            # Try common column name variations
            if 'Spam/Ham' in enron.columns:
                enron['label'] = enron['Spam/Ham'].map({'spam': 1, 'ham': 0})
                text_col = 'Message' if 'Message' in enron.columns else 'Subject'
                enron['text'] = enron[text_col].apply(clean_text)
            elif 'label' in enron.columns:
                enron['label'] = enron['label']
                enron['text']  = enron['text'].apply(clean_text)
            else:
                # Fallback: use first two columns
                enron.columns = ['label_text', 'text'] + list(enron.columns[2:])
                enron['label'] = enron['label_text'].map(
                    {'spam': 1, 'ham': 0, '1': 1, '0': 0})
                enron['text'] = enron['text'].apply(clean_text)

            enron = enron[['text', 'label']].dropna()
            enron = enron[enron['label'].isin([0, 1])]
            enron['source'] = 'enron'
            # Cap at 15000 to keep balance manageable
            enron = enron.sample(min(15000, len(enron)), random_state=42)
            frames.append(enron)
            print(f"  Enron rows:      {len(enron)}")
        except Exception as e:
            print(f"  Enron skipped: {e}")
    else:
        print("  Enron data not found — skipping")

    # ── 4. Merge and deduplicate ───────────────────────────────────────────
    df = pd.concat(frames, ignore_index=True)
    df = df.drop_duplicates(subset='text')
    df = df[df['text'].str.len() > 5]  # remove very short rows

    print(f"\n  Class balance:")
    print(f"  {df['label'].value_counts().to_dict()}")
    print(f"  Total rows: {len(df)}")

    # ── 5. Train / val / test split ────────────────────────────────────────
    train, temp = train_test_split(df, test_size=0.30,
                                   random_state=42, stratify=df['label'])
    val, test   = train_test_split(temp, test_size=0.50,
                                   random_state=42, stratify=temp['label'])

    train.to_csv("data/processed/text_train.csv", index=False)
    val.to_csv("data/processed/text_val.csv",     index=False)
    test.to_csv("data/processed/text_test.csv",   index=False)
    df.to_csv(OUT_TEXT, index=False)

    print(f"\n  Split → Train: {len(train)}  "
          f"Val: {len(val)}  Test: {len(test)}")
    print("  Saved to data/processed/")


def build_url_dataset():
    seed = pd.read_csv(SEED_URL)[['url', 'label']].dropna()
    seed['source'] = 'seed'
    print(f"\n  URL rows: {len(seed)}")
    seed.to_csv(OUT_URL, index=False)
    print(f"  Saved to {OUT_URL}")


def build_upi_dataset():
    seed = pd.read_csv(SEED_UPI)[['text', 'label', 'category']].dropna()
    seed['text'] = seed['text'].apply(clean_text)
    seed['source'] = 'seed'
    print(f"\n  UPI rows: {len(seed)}")
    seed.to_csv(OUT_UPI, index=False)
    print(f"  Saved to {OUT_UPI}")


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

    print("\n✅ All datasets prepared.")
    print("Next: python3 ml/train.py")
