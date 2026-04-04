"""
ML Detection Engine
Loads trained TF-IDF + Logistic Regression model and predicts scam probability.
"""

import joblib
import os
import json
from app.utils.text_cleaner import clean_text_for_ml

MODEL_PATH      = "models/scam_classifier.pkl"
VECTORIZER_PATH = "models/tfidf_vectorizer.pkl"
METRICS_PATH    = "models/metrics.json"

_model       = None
_vectorizer  = None
_metrics     = {}
_model_ready = False


def load_model():
    """Load model and vectorizer from disk. Call once at startup."""
    global _model, _vectorizer, _metrics, _model_ready

    if not os.path.exists(MODEL_PATH):
        print(f"WARNING: Model not found at {MODEL_PATH}")
        print("Run: python3 ml/train.py")
        _model_ready = False
        return False

    if not os.path.exists(VECTORIZER_PATH):
        print(f"WARNING: Vectorizer not found at {VECTORIZER_PATH}")
        _model_ready = False
        return False

    try:
        _model      = joblib.load(MODEL_PATH)
        _vectorizer = joblib.load(VECTORIZER_PATH)
        _model_ready = True

        if os.path.exists(METRICS_PATH):
            with open(METRICS_PATH) as f:
                _metrics = json.load(f)

        print(f"ML model loaded. Test accuracy: {_metrics.get('test_accuracy', 'N/A')}")
        return True

    except Exception as e:
        print(f"ERROR loading model: {e}")
        _model_ready = False
        return False


def analyze_text(text: str) -> dict:
    """Predict scam probability for input text. Returns score 0-100."""

    if not _model_ready or _model is None or _vectorizer is None:
        return {
            "score": 0,
            "probability": 0.0,
            "prediction": "unknown",
            "model_ready": False,
            "reasons": ["ML model not loaded — run python3 ml/train.py first"]
        }

    if not text or not text.strip():
        return {
            "score": 0,
            "probability": 0.0,
            "prediction": "safe",
            "model_ready": True,
            "reasons": []
        }

    try:
        cleaned   = clean_text_for_ml(text)
        vec       = _vectorizer.transform([cleaned])
        proba     = _model.predict_proba(vec)[0]
        scam_prob = float(proba[1])
        score     = round(scam_prob * 100)

        reasons = []
        if scam_prob >= 0.85:
            reasons.append(
                f"ML model is {scam_prob*100:.0f}% confident this is a scam"
            )
        elif scam_prob >= 0.55:
            reasons.append(
                f"ML model detects suspicious patterns "
                f"(confidence: {scam_prob*100:.0f}%)"
            )

        return {
            "score":       score,
            "probability": round(scam_prob, 4),
            "prediction":  "scam" if scam_prob >= 0.55 else "safe",
            "model_ready": True,
            "reasons":     reasons
        }

    except Exception as e:
        return {
            "score": 0,
            "probability": 0.0,
            "prediction": "error",
            "model_ready": True,
            "reasons": [f"ML analysis error: {str(e)}"]
        }


def get_model_info() -> dict:
    """Returns model metadata for the /health endpoint."""
    return {
        "model_ready":   _model_ready,
        "test_accuracy": _metrics.get("test_accuracy"),
        "test_f1":       _metrics.get("test_f1"),
        "train_rows":    _metrics.get("train_rows"),
        "vocab_size":    _metrics.get("vocab_size"),
    }
