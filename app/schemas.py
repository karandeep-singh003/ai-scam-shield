"""
Pydantic schemas for request and response validation.
FastAPI uses these to auto-validate inputs and generate Swagger docs.
"""

from pydantic import BaseModel, Field
from typing import Optional


# ── Request schemas ────────────────────────────────────────────────────────

class TextAnalysisRequest(BaseModel):
    text: str = Field(
        ...,
        min_length=1,
        max_length=5000,
        description="The SMS, message, or text to analyze",
        example="Dear customer your SBI account is blocked. Update KYC at http://sbi-kyc.xyz immediately"
    )

class URLAnalysisRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=4,
        max_length=2000,
        description="The URL to analyze for phishing indicators",
        example="http://sbi-kyc-update.xyz/login/verify"
    )

class UPIAnalysisRequest(BaseModel):
    text: str = Field(
        ...,
        min_length=1,
        max_length=5000,
        description="The UPI-related message or prompt to analyze",
        example="Enter your UPI PIN to receive Rs 500 cashback from PhonePe"
    )

class FullAnalysisRequest(BaseModel):
    text: Optional[str] = Field(
        None,
        max_length=5000,
        description="Text or SMS message to analyze"
    )
    url: Optional[str] = Field(
        None,
        max_length=2000,
        description="URL to analyze"
    )


# ── Response schemas ───────────────────────────────────────────────────────

class ScoreBreakdown(BaseModel):
    rule_engine: float
    ml_engine:   float
    url_engine:  float
    upi_engine:  float

class AnalysisResponse(BaseModel):
    is_scam:         bool
    risk_score:      float
    threat_level:    str
    category:        str
    reasons:         list[str]
    advice:          str
    score_breakdown: ScoreBreakdown
    ml_probability:  float

class HealthResponse(BaseModel):
    status:        str
    message:       str
    model_ready:   bool
    test_accuracy: Optional[float]
    test_f1:       Optional[float]
    train_rows:    Optional[int]
    vocab_size:    Optional[int]
