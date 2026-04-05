🛡️ AI Scam Shield

> An AI-powered detection system for social engineering, phishing URLs, SMS scams, and UPI fraud — built for real-world deployment.

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com)
[![ML Accuracy](https://img.shields.io/badge/ML%20Accuracy-98.22%25-brightgreen.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](#license)
[![Live API](https://img.shields.io/badge/API-Live%20on%20Render-success.svg)](https://ai-scam-shield-dbp1.onrender.com/health)

---

🌐 Live Demo

| Resource | URL |
|---|---|
| 🔗 API Health | [/health](https://ai-scam-shield-dbp1.onrender.com/health) |
| 📖 Swagger Docs | [/docs](https://ai-scam-shield-dbp1.onrender.com/docs) |
| 🖥️ Frontend UI | [GitHub Pages](https://karandeepsingh004.github.io/ai-scam-shield) |

---

 📌 Project Overview

AI Scam Shield is a hybrid AI + rule-based scam detection system designed
specifically for the Indian digital payments ecosystem. It detects:

- 📱 **SMS & social engineering scams** — KYC fraud, OTP harvesting, fake prizes
- 🔗 **Phishing URLs** — fake bank sites, brand impersonation, suspicious domains
- 💳 **UPI fraud** — PIN harvest scams, collect request fraud, fake refunds
- ⚠️ **Risk scoring** — unified 0–100 score with Low/Medium/High/Critical levels

---

🏗️ ArchitectureUser Input (Text / URL / UPI)
│
▼
FastAPI Backend
│
┌────┴─────────────────────┐
│                          │
▼                          ▼
Rule Engine              ML Engine
(Regex + Keywords)       (TF-IDF + LR)
│                          │
▼                          ▼
URL Engine               UPI Engine
(Heuristics)             (India-specific)
│                          │
└────────────┬─────────────┘
▼
Risk Scoring Engine
(Weighted combination)
│
▼
JSON Response
(score + level + reasons + advice)

---

 🧠 Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.11+ |
| API Framework | FastAPI |
| ML Model | TF-IDF + Logistic Regression (scikit-learn) |
| Data | Kaggle SMS Spam + India-specific seed data |
| Serialization | joblib |
| Validation | Pydantic v2 |
| Testing | pytest |
| Deployment | Docker + Render |
| Frontend | HTML + Vanilla JS |

---

 📊 Model Performance

| Metric | Score |
|---|---|
| Accuracy | **98.22%** |
| Precision | **95.31%** |
| Recall | **93.13%** |
| F1 Score | **94.21%** |
| Training rows | 3,941 |
| Vocabulary size | 9,132 tokens |

---

 📁 Folder Structureai-scam-shield/
├── app/
│   ├── main.py              # FastAPI app + all endpoints
│   ├── schemas.py           # Pydantic request/response models
│   ├── config.py            # Score weights + thresholds
│   ├── engines/
│   │   ├── rule_engine.py   # Regex + keyword detection
│   │   ├── ml_engine.py     # ML model loader + predictor
│   │   ├── url_engine.py    # URL heuristic analysis
│   │   ├── upi_engine.py    # UPI fraud patterns
│   │   └── risk_scorer.py   # Unified score combiner
│   └── utils/
│       └── text_cleaner.py  # Shared preprocessing
├── ml/
│   ├── train.py             # Model training script
│   ├── prepare_data.py      # Dataset preparation
│   └── generate_synthetic.py# India-specific data generator
├── data/
│   ├── processed/           # Train/val/test splits
│   └── seed/                # Hand-crafted India-specific examples
├── models/
│   ├── scam_classifier.pkl  # Trained model
│   └── tfidf_vectorizer.pkl # Fitted vectorizer
├── frontend/
│   └── index.html           # Demo UI
├── tests/                   # pytest test suite
├── Dockerfile
├── docker-compose.yml
└── requirements.txt

---

🚀 Run Locally

Prerequisites
- Python 3.10+
- pip

 Setup
```bashClone the repository
git clone https://github.com/karandeepsingh004/ai-scam-shield.git
cd ai-scam-shieldCreate virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activateInstall dependencies
pip install -r requirements.txtTrain the model (first time only)
python3 ml/prepare_data.py
python3 ml/train.pyStart the API
uvicorn app.main:app --reload --port 8000

Visit `http://localhost:8000/docs` for the interactive API.

---

 🐳 Run with Docker
```bashdocker build -t ai-scam-shield .
docker run -p 8000:8000 ai-scam-shield
---
📡 API Endpoints
 GET /health
Check API status and model info.

**Response:**
```json{
"status": "ok",
"model_ready": true,
"test_accuracy": 0.9822,
"test_f1": 0.9421
}

---

 POST /analyze/text
Analyze any SMS or text message.

**Request:**
```json{
"text": "Enter your UPI PIN to receive Rs 500 cashback from PhonePe"
}

**Response:**
```json{
"is_scam": true,
"risk_score": 87,
"threat_level": "Critical",
"category": "UPI PIN Harvest",
"reasons": [
"Asks for UPI PIN — you NEVER need PIN to receive money",
"ML model is 91% confident this is a scam"
],
"advice": "NEVER enter your UPI PIN to receive money...",
"score_breakdown": {
"rule_engine": 95,
"ml_engine": 91,
"url_engine": 0,
"upi_engine": 95
},
"ml_probability": 0.91
}

---

 POST /analyze/url
Analyze a URL for phishing indicators.

**Request:**
```json{
"url": "http://sbi-kyc-update.xyz/login/verify"
}

---

 POST /analyze/upi
Analyze a UPI-related message.

**Request:**
```json{
"text": "Scan QR code to receive Rs 25000 prize from PhonePe"
}

---

 POST /analyze/all
Analyze both text and URL together.

**Request:**
```json{
"text": "Click this link to update KYC",
"url": "http://sbi-kyc.xyz/update"
}

---

 🧪 Running Tests
```bashpytest tests/test_rule_engine.py -v
python3 tests/test_engines.py

---

 🔍 Detection Capabilities

 Rule Engine Patterns
- KYC scams, OTP harvesting, account block threats
- Fake refunds, UPI PIN harvest, lottery scams
- Credential harvesting, Aadhaar/PAN data theft
- Advance fee fraud, phishing call-to-actions

 URL Heuristics
- IP address as host
- Suspicious TLDs (.xyz, .info, .online, .tk)
- Brand impersonation (SBI, HDFC, Paytm, PhonePe)
- Subdomain abuse, hyphen abuse, typosquatting
- Phishing keywords in URL path

 UPI Fraud Patterns
- PIN harvest contradiction detection
- Collect request fraud
- Fake refund / cashback scams
- QR code scams
- KYC + UPI combinations
- Fake support impersonation

---
 ⚠️ Limitations

- SMS dataset is primarily English — Hindi/Hinglish scams may have lower detection rate
- URL engine is heuristic-based — novel phishing domains may be missed
- Model trained on 3,941 samples — production system would need millions
- Free tier deployment has cold start delay of ~30 seconds after inactivity

---
 🔮 Future Improvements

- [ ] Hindi/Hinglish NLP support using multilingual BERT
- [ ] Real-time WHOIS domain age checking for URLs
- [ ] Browser extension integration
- [ ] Mobile app (React Native)
- [ ] Feedback loop — users report false positives to retrain model
- [ ] Integration with NPCI fraud database
- [ ] WhatsApp Business API integration

---
👨‍💻 Author
**Karandeep Singh**
Final Year Project — AI/ML + Cybersecurity
GitHub: [@karandeepsingh004](https://github.com/karandeepsingh004)

---
📄 License

MIT License — free to use, modify, and distribute with attribution.

---
 🙏 Acknowledgements

- UCI ML Repository — SMS Spam Collection Dataset
- Kaggle — SMS Spam dataset
- NPCI — UPI fraud pattern research
- scikit-learn, FastAPI, and the open source community
