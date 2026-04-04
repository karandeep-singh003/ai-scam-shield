"""
ML Model Training Script
Run: python3 ml/train.py
"""

print("Starting training script...")

import pandas as pd
import numpy as np
import joblib
import os
import json

print("Imports done.")

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report
)
from sklearn.utils.class_weight import compute_class_weight

print("Sklearn imports done.")

os.makedirs("models", exist_ok=True)

# ── Load data ──────────────────────────────────────────────────────────────
print("\nLoading datasets...")
train = pd.read_csv("data/processed/text_train.csv")
val   = pd.read_csv("data/processed/text_val.csv")
test  = pd.read_csv("data/processed/text_test.csv")

train = train.dropna(subset=['text', 'label'])
val   = val.dropna(subset=['text', 'label'])
test  = test.dropna(subset=['text', 'label'])

X_train = train['text'].astype(str)
y_train = train['label'].astype(int)
X_val   = val['text'].astype(str)
y_val   = val['label'].astype(int)
X_test  = test['text'].astype(str)
y_test  = test['label'].astype(int)

print(f"Train: {len(X_train)} rows")
print(f"Val:   {len(X_val)} rows")
print(f"Test:  {len(X_test)} rows")
print(f"Class balance: {dict(y_train.value_counts())}")

# ── TF-IDF ─────────────────────────────────────────────────────────────────
print("\nFitting TF-IDF vectorizer...")
vectorizer = TfidfVectorizer(
    max_features=10000,
    ngram_range=(1, 2),
    min_df=2,
    max_df=0.95,
    sublinear_tf=True,
    strip_accents='unicode',
    analyzer='word',
)

X_train_vec = vectorizer.fit_transform(X_train)
X_val_vec   = vectorizer.transform(X_val)
X_test_vec  = vectorizer.transform(X_test)
print(f"Vocabulary size: {len(vectorizer.vocabulary_)}")

# ── Class weights ──────────────────────────────────────────────────────────
print("\nComputing class weights...")
classes      = np.unique(y_train)
class_weights = compute_class_weight('balanced', classes=classes, y=y_train)
weight_dict   = dict(zip(classes, class_weights))
print(f"Class weights: {weight_dict}")

# ── Train model ────────────────────────────────────────────────────────────
print("\nTraining Logistic Regression...")
model = LogisticRegression(
    C=1.0,
    max_iter=1000,
    class_weight='balanced',
    solver='lbfgs',
    random_state=42
)
model.fit(X_train_vec, y_train)
print("Training complete.")

# ── Validation results ─────────────────────────────────────────────────────
print("\n" + "=" * 50)
print("VALIDATION RESULTS")
print("=" * 50)
y_val_pred = model.predict(X_val_vec)
print(f"Accuracy:  {accuracy_score(y_val, y_val_pred):.4f}")
print(f"Precision: {precision_score(y_val, y_val_pred, zero_division=0):.4f}")
print(f"Recall:    {recall_score(y_val, y_val_pred, zero_division=0):.4f}")
print(f"F1 Score:  {f1_score(y_val, y_val_pred, zero_division=0):.4f}")

cm = confusion_matrix(y_val, y_val_pred)
print(f"\nConfusion Matrix:")
print(f"              Predicted SAFE  Predicted SCAM")
print(f"Actual SAFE        {cm[0][0]:>8}        {cm[0][1]:>8}")
print(f"Actual SCAM        {cm[1][0]:>8}        {cm[1][1]:>8}")

# ── Test results ───────────────────────────────────────────────────────────
print("\n" + "=" * 50)
print("TEST RESULTS")
print("=" * 50)
y_test_pred = model.predict(X_test_vec)
test_acc  = accuracy_score(y_test, y_test_pred)
test_prec = precision_score(y_test, y_test_pred, zero_division=0)
test_rec  = recall_score(y_test, y_test_pred, zero_division=0)
test_f1   = f1_score(y_test, y_test_pred, zero_division=0)

print(f"Accuracy:  {test_acc:.4f}  ({test_acc*100:.2f}%)")
print(f"Precision: {test_prec:.4f}")
print(f"Recall:    {test_rec:.4f}")
print(f"F1 Score:  {test_f1:.4f}")

cm_test = confusion_matrix(y_test, y_test_pred)
print(f"\nConfusion Matrix:")
print(f"              Predicted SAFE  Predicted SCAM")
print(f"Actual SAFE        {cm_test[0][0]:>8}        {cm_test[0][1]:>8}")
print(f"Actual SCAM        {cm_test[1][0]:>8}        {cm_test[1][1]:>8}")

# ── Top scam words ─────────────────────────────────────────────────────────
print("\n" + "=" * 50)
print("TOP 15 SCAM INDICATOR WORDS")
print("=" * 50)
feature_names = vectorizer.get_feature_names_out()
scam_coefs    = model.coef_[0]
top_idx       = np.argsort(scam_coefs)[-15:][::-1]
for idx in top_idx:
    print(f"  {feature_names[idx]:<25} {scam_coefs[idx]:.4f}")

# ── Save ───────────────────────────────────────────────────────────────────
print("\n" + "=" * 50)
print("SAVING MODEL FILES")
print("=" * 50)
joblib.dump(model,      "models/scam_classifier.pkl")
joblib.dump(vectorizer, "models/tfidf_vectorizer.pkl")

metrics = {
    "test_accuracy":  round(float(test_acc),  4),
    "test_precision": round(float(test_prec), 4),
    "test_recall":    round(float(test_rec),  4),
    "test_f1":        round(float(test_f1),   4),
    "train_rows":     int(len(X_train)),
    "val_rows":       int(len(X_val)),
    "test_rows":      int(len(X_test)),
    "vocab_size":     int(len(vectorizer.vocabulary_)),
}
with open("models/metrics.json", "w") as f:
    json.dump(metrics, f, indent=2)

print("Saved: models/scam_classifier.pkl")
print("Saved: models/tfidf_vectorizer.pkl")
print("Saved: models/metrics.json")
print("\n✅ Training complete!")
print(f"   Final accuracy: {test_acc*100:.2f}%")
print(f"   Final F1:       {test_f1:.4f}")
print("\nNext: python3 tests/test_engines.py")
