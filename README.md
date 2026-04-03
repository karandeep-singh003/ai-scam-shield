# AI Scam Shield
### AI-Powered Detection System for Social Engineering, Fake Websites, SMS and UPI Scam Detection

AI Scam Shield is a **hybrid cybersecurity detection platform** designed to identify and explain common digital scam patterns including:

- **Social engineering & impersonation scams**
- **Phishing SMS / scam text messages**
- **Fake websites / phishing URLs**
- **UPI fraud prompts (collect request scams, PIN harvest, fake refunds, QR scams)**
- **Risk-based fraud indicators with explainable reasons**

This project is built as a **final-year academic project** with a strong focus on **real-world implementation**, **deployment readiness**, and future extensibility into:

- Browser extensions
- Mobile applications
- Cybersecurity awareness tools
- Scam detection APIs
- Fraud alert systems

---

## 🚀 Project Vision

Traditional spam filters often fail against modern scam campaigns because scams are:

- Contextual
- Emotionally manipulative
- Rapidly changing
- Multi-channel (SMS + URLs + UPI + impersonation)

**AI Scam Shield** solves this using a **hybrid detection architecture** that combines:

1. **Rule-based detection** for high-confidence scam patterns
2. **Machine learning text classification** for scam vs non-scam language
3. **URL heuristic analysis** for phishing website detection
4. **India-specific UPI scam logic** for real-world fraud patterns
5. **Unified risk scoring engine** for consistent explainable output

---

## ✨ Key Features

- 🔍 Detects **phishing SMS and scam text**
- 🌐 Detects **fake/phishing URLs**
- 💸 Detects **UPI-specific fraud patterns** (India-focused)
- 🧠 Uses **TF-IDF + Logistic Regression** for scam text classification
- ⚙️ Uses **rule-based detection** for explainable high-confidence patterns
- 📊 Returns **risk score (0–100)**
- 🚨 Returns **threat level**:
  - Low
  - Medium
  - High
  - Critical
- 🏷️ Classifies scam category:
  - KYC scam
  - OTP scam
  - Refund scam
  - UPI PIN harvest
  - Collect request scam
  - Phishing URL
  - Impersonation / support fraud
- 📝 Provides **human-readable reasons**
- 🛡️ Provides **actionable safety advice**
- ⚡ Built with **FastAPI** for production-ready API support
- 📚 Includes **Swagger UI** documentation
- 🧪 Includes **testing support**
- 🐳 Deployment-ready with **Docker**

---

## 🏗️ Final Architecture

### High-Level System Design

```text
User Input (Text / URL / UPI Prompt)
            │
            ▼
      FastAPI REST API
            │
            ▼
   Detection Orchestration Layer
            │
            ├── Rule-Based Detection Engine
            │      ├── KYC / OTP / urgency scams
            │      ├── refund scams
            │      ├── impersonation scams
            │      └── suspicious keyword/regex patterns
            │
            ├── ML Text Classifier
            │      └── TF-IDF + Logistic Regression
            │
            ├── URL Heuristic Engine
            │      ├── suspicious TLDs
            │      ├── IP-based hosts
            │      ├── phishing keywords
            │      ├── brand impersonation
            │      └── typo / hyphen abuse
            │
            └── UPI Fraud Engine
                   ├── PIN harvest scams
                   ├── collect request fraud
                   ├── fake refund scams
                   ├── QR scams
                   └── reward / cashback scams
            │
            ▼
      Unified Risk Scoring Engine
            │
            ▼
   JSON Response with:
   - is_scam
   - risk_score
   - threat_level
   - category
   - reasons
   - safety_advice
