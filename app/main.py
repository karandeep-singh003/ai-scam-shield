"""
AI Scam Shield — FastAPI Backend
==================================
All API endpoints live here.
Run with: uvicorn app.main:app --reload --port 8000
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import logging

from app.schemas import (
    TextAnalysisRequest, URLAnalysisRequest,
    UPIAnalysisRequest, FullAnalysisRequest,
    AnalysisResponse, HealthResponse, ScoreBreakdown
)
from app.engines import rule_engine, ml_engine, url_engine, upi_engine
from app.engines.risk_scorer import calculate_risk
from app.config import APP_TITLE, APP_VERSION, APP_DESCRIPTION

# ── Logging setup ──────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# ── FastAPI app ────────────────────────────────────────────────────────────
app = FastAPI(
    title=APP_TITLE,
    version=APP_VERSION,
    description=APP_DESCRIPTION,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS — allows frontend and browser extensions to call the API ──────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Load ML model on startup ───────────────────────────────────────────────
@app.on_event("startup")
async def startup_event():
    logger.info("Starting AI Scam Shield API...")
    loaded = ml_engine.load_model()
    if loaded:
        logger.info("ML model loaded successfully.")
    else:
        logger.warning("ML model not loaded. Run python3 ml/train.py first.")


# ══════════════════════════════════════════════════════════════════════════
# ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════

@app.get("/health", response_model=HealthResponse, tags=["System"])
def health_check():
    """
    Check if the API and ML model are running correctly.
    Use this to verify deployment is working.
    """
    info = ml_engine.get_model_info()
    return HealthResponse(
        status="ok",
        message="AI Scam Shield is running",
        model_ready=info.get("model_ready", False),
        test_accuracy=info.get("test_accuracy"),
        test_f1=info.get("test_f1"),
        train_rows=info.get("train_rows"),
        vocab_size=info.get("vocab_size"),
    )


@app.post("/analyze/text", response_model=AnalysisResponse, tags=["Analysis"])
def analyze_text(request: TextAnalysisRequest):
    """
    Analyze any SMS, message, or text for scam indicators.

    Runs through:
    - Rule-based engine (keyword + regex patterns)
    - ML classifier (TF-IDF + Logistic Regression)
    - UPI fraud detector (India-specific patterns)
    - URL extractor (if URLs found in text)

    Returns risk score 0-100, threat level, category, reasons, and advice.
    """
    try:
        text = request.text
        logger.info(f"Analyzing text: {text[:60]}...")

        # ── Run all engines ────────────────────────────────────────────────
        rule_result = rule_engine.analyze_text(text)
        ml_result   = ml_engine.analyze_text(text)
        upi_result  = upi_engine.analyze_upi(text)

        # ── If text contains URLs, analyze the first one ───────────────────
        extracted_urls = rule_result.get("extracted_urls", [])
        if extracted_urls:
            url_result = url_engine.analyze_url(extracted_urls[0])
            logger.info(f"URL found in text: {extracted_urls[0]}")
        else:
            url_result = {"score": 0, "reasons": [], "is_trusted": False, "domain": ""}

        # ── Combine into final score ───────────────────────────────────────
        final = calculate_risk(
            rule_result, ml_result, url_result, upi_result,
            input_type="text"
        )

        logger.info(
            f"Result: score={final['risk_score']} "
            f"level={final['threat_level']} "
            f"scam={final['is_scam']}"
        )

        return AnalysisResponse(
            is_scam=final["is_scam"],
            risk_score=final["risk_score"],
            threat_level=final["threat_level"],
            category=final["category"],
            reasons=final["reasons"],
            advice=final["advice"],
            score_breakdown=ScoreBreakdown(
                rule_engine=final["score_breakdown"]["rule_engine"],
                ml_engine=final["score_breakdown"]["ml_engine"],
                url_engine=final["score_breakdown"]["url_engine"],
                upi_engine=final["score_breakdown"]["upi_engine"],
            ),
            ml_probability=final["ml_probability"],
        )

    except Exception as e:
        logger.error(f"Error analyzing text: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze/url", response_model=AnalysisResponse, tags=["Analysis"])
def analyze_url_endpoint(request: URLAnalysisRequest):
    """
    Analyze a URL for phishing indicators.

    Checks for:
    - IP address hosts
    - Suspicious TLDs (.xyz, .info, .online)
    - Brand impersonation (fake SBI, HDFC, Paytm domains)
    - Subdomain abuse
    - Phishing keywords in path
    - HTTP on financial sites
    """
    try:
        url = request.url
        logger.info(f"Analyzing URL: {url}")

        rule_result = rule_engine.analyze_text(url)
        ml_result   = ml_engine.analyze_text(url)
        url_result  = url_engine.analyze_url(url)
        upi_result  = {"score": 0, "reasons": [], "advice": "",
                       "category": "N/A", "is_upi_related": False}

        final = calculate_risk(
            rule_result, ml_result, url_result, upi_result,
            input_type="url"
        )

        logger.info(
            f"URL Result: score={final['risk_score']} "
            f"level={final['threat_level']}"
        )

        return AnalysisResponse(
            is_scam=final["is_scam"],
            risk_score=final["risk_score"],
            threat_level=final["threat_level"],
            category=final["category"],
            reasons=final["reasons"],
            advice=final["advice"],
            score_breakdown=ScoreBreakdown(
                rule_engine=final["score_breakdown"]["rule_engine"],
                ml_engine=final["score_breakdown"]["ml_engine"],
                url_engine=final["score_breakdown"]["url_engine"],
                upi_engine=final["score_breakdown"]["upi_engine"],
            ),
            ml_probability=final["ml_probability"],
        )

    except Exception as e:
        logger.error(f"Error analyzing URL: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze/upi", response_model=AnalysisResponse, tags=["Analysis"])
def analyze_upi_endpoint(request: UPIAnalysisRequest):
    """
    Analyze a UPI-related message for India-specific fraud patterns.

    Detects:
    - UPI PIN harvest scams
    - Collect request fraud
    - Fake refund scams
    - QR code scams
    - Fake cashback/reward fraud
    - KYC + UPI combinations
    - Fake support impersonation
    """
    try:
        text = request.text
        logger.info(f"Analyzing UPI text: {text[:60]}...")

        rule_result = rule_engine.analyze_text(text)
        ml_result   = ml_engine.analyze_text(text)
        upi_result  = upi_engine.analyze_upi(text)
        url_result  = {"score": 0, "reasons": [], "is_trusted": False, "domain": ""}

        final = calculate_risk(
            rule_result, ml_result, url_result, upi_result,
            input_type="upi"
        )

        logger.info(
            f"UPI Result: score={final['risk_score']} "
            f"category={final['category']}"
        )

        return AnalysisResponse(
            is_scam=final["is_scam"],
            risk_score=final["risk_score"],
            threat_level=final["threat_level"],
            category=final["category"],
            reasons=final["reasons"],
            advice=final["advice"],
            score_breakdown=ScoreBreakdown(
                rule_engine=final["score_breakdown"]["rule_engine"],
                ml_engine=final["score_breakdown"]["ml_engine"],
                url_engine=final["score_breakdown"]["url_engine"],
                upi_engine=final["score_breakdown"]["upi_engine"],
            ),
            ml_probability=final["ml_probability"],
        )

    except Exception as e:
        logger.error(f"Error analyzing UPI text: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze/all", response_model=AnalysisResponse, tags=["Analysis"])
def analyze_all(request: FullAnalysisRequest):
    """
    Analyze both text and URL together in one request.
    Use this when you have both a message body and a URL to check.
    """
    try:
        if not request.text and not request.url:
            raise HTTPException(
                status_code=400,
                detail="Provide at least one of: text, url"
            )

        text = request.text or ""
        url  = request.url or ""

        rule_result = rule_engine.analyze_text(text or url)
        ml_result   = ml_engine.analyze_text(text or url)
        upi_result  = upi_engine.analyze_upi(text)
        url_result  = url_engine.analyze_url(url) if url else \
                      {"score": 0, "reasons": [], "is_trusted": False, "domain": ""}

        final = calculate_risk(
            rule_result, ml_result, url_result, upi_result,
            input_type="text"
        )

        return AnalysisResponse(
            is_scam=final["is_scam"],
            risk_score=final["risk_score"],
            threat_level=final["threat_level"],
            category=final["category"],
            reasons=final["reasons"],
            advice=final["advice"],
            score_breakdown=ScoreBreakdown(
                rule_engine=final["score_breakdown"]["rule_engine"],
                ml_engine=final["score_breakdown"]["ml_engine"],
                url_engine=final["score_breakdown"]["url_engine"],
                upi_engine=final["score_breakdown"]["upi_engine"],
            ),
            ml_probability=final["ml_probability"],
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in analyze/all: {e}")
        raise HTTPException(status_code=500, detail=str(e))
"""
AI Scam Shield — FastAPI Backend
==================================
All API endpoints live here.
Run with: uvicorn app.main:app --reload --port 8000
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import logging

from app.schemas import (
    TextAnalysisRequest, URLAnalysisRequest,
    UPIAnalysisRequest, FullAnalysisRequest,
    AnalysisResponse, HealthResponse, ScoreBreakdown
)
from app.engines import rule_engine, ml_engine, url_engine, upi_engine
from app.engines.risk_scorer import calculate_risk
from app.config import APP_TITLE, APP_VERSION, APP_DESCRIPTION

# ── Logging setup ──────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# ── FastAPI app ────────────────────────────────────────────────────────────
app = FastAPI(
    title=APP_TITLE,
    version=APP_VERSION,
    description=APP_DESCRIPTION,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS — allows frontend and browser extensions to call the API ──────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Load ML model on startup ───────────────────────────────────────────────
@app.on_event("startup")
async def startup_event():
    logger.info("Starting AI Scam Shield API...")
    loaded = ml_engine.load_model()
    if loaded:
        logger.info("ML model loaded successfully.")
    else:
        logger.warning("ML model not loaded. Run python3 ml/train.py first.")


# ══════════════════════════════════════════════════════════════════════════
# ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════

@app.get("/health", response_model=HealthResponse, tags=["System"])
def health_check():
    """
    Check if the API and ML model are running correctly.
    Use this to verify deployment is working.
    """
    info = ml_engine.get_model_info()
    return HealthResponse(
        status="ok",
        message="AI Scam Shield is running",
        model_ready=info.get("model_ready", False),
        test_accuracy=info.get("test_accuracy"),
        test_f1=info.get("test_f1"),
        train_rows=info.get("train_rows"),
        vocab_size=info.get("vocab_size"),
    )


@app.post("/analyze/text", response_model=AnalysisResponse, tags=["Analysis"])
def analyze_text(request: TextAnalysisRequest):
    """
    Analyze any SMS, message, or text for scam indicators.

    Runs through:
    - Rule-based engine (keyword + regex patterns)
    - ML classifier (TF-IDF + Logistic Regression)
    - UPI fraud detector (India-specific patterns)
    - URL extractor (if URLs found in text)

    Returns risk score 0-100, threat level, category, reasons, and advice.
    """
    try:
        text = request.text
        logger.info(f"Analyzing text: {text[:60]}...")

        # ── Run all engines ────────────────────────────────────────────────
        rule_result = rule_engine.analyze_text(text)
        ml_result   = ml_engine.analyze_text(text)
        upi_result  = upi_engine.analyze_upi(text)

        # ── If text contains URLs, analyze the first one ───────────────────
        extracted_urls = rule_result.get("extracted_urls", [])
        if extracted_urls:
            url_result = url_engine.analyze_url(extracted_urls[0])
            logger.info(f"URL found in text: {extracted_urls[0]}")
        else:
            url_result = {"score": 0, "reasons": [], "is_trusted": False, "domain": ""}

        # ── Combine into final score ───────────────────────────────────────
        final = calculate_risk(
            rule_result, ml_result, url_result, upi_result,
            input_type="text"
        )

        logger.info(
            f"Result: score={final['risk_score']} "
            f"level={final['threat_level']} "
            f"scam={final['is_scam']}"
        )

        return AnalysisResponse(
            is_scam=final["is_scam"],
            risk_score=final["risk_score"],
            threat_level=final["threat_level"],
            category=final["category"],
            reasons=final["reasons"],
            advice=final["advice"],
            score_breakdown=ScoreBreakdown(
                rule_engine=final["score_breakdown"]["rule_engine"],
                ml_engine=final["score_breakdown"]["ml_engine"],
                url_engine=final["score_breakdown"]["url_engine"],
                upi_engine=final["score_breakdown"]["upi_engine"],
            ),
            ml_probability=final["ml_probability"],
        )

    except Exception as e:
        logger.error(f"Error analyzing text: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze/url", response_model=AnalysisResponse, tags=["Analysis"])
def analyze_url_endpoint(request: URLAnalysisRequest):
    """
    Analyze a URL for phishing indicators.

    Checks for:
    - IP address hosts
    - Suspicious TLDs (.xyz, .info, .online)
    - Brand impersonation (fake SBI, HDFC, Paytm domains)
    - Subdomain abuse
    - Phishing keywords in path
    - HTTP on financial sites
    """
    try:
        url = request.url
        logger.info(f"Analyzing URL: {url}")

        rule_result = rule_engine.analyze_text(url)
        ml_result   = ml_engine.analyze_text(url)
        url_result  = url_engine.analyze_url(url)
        upi_result  = {"score": 0, "reasons": [], "advice": "",
                       "category": "N/A", "is_upi_related": False}

        final = calculate_risk(
            rule_result, ml_result, url_result, upi_result,
            input_type="url"
        )

        logger.info(
            f"URL Result: score={final['risk_score']} "
            f"level={final['threat_level']}"
        )

        return AnalysisResponse(
            is_scam=final["is_scam"],
            risk_score=final["risk_score"],
            threat_level=final["threat_level"],
            category=final["category"],
            reasons=final["reasons"],
            advice=final["advice"],
            score_breakdown=ScoreBreakdown(
                rule_engine=final["score_breakdown"]["rule_engine"],
                ml_engine=final["score_breakdown"]["ml_engine"],
                url_engine=final["score_breakdown"]["url_engine"],
                upi_engine=final["score_breakdown"]["upi_engine"],
            ),
            ml_probability=final["ml_probability"],
        )

    except Exception as e:
        logger.error(f"Error analyzing URL: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze/upi", response_model=AnalysisResponse, tags=["Analysis"])
def analyze_upi_endpoint(request: UPIAnalysisRequest):
    """
    Analyze a UPI-related message for India-specific fraud patterns.

    Detects:
    - UPI PIN harvest scams
    - Collect request fraud
    - Fake refund scams
    - QR code scams
    - Fake cashback/reward fraud
    - KYC + UPI combinations
    - Fake support impersonation
    """
    try:
        text = request.text
        logger.info(f"Analyzing UPI text: {text[:60]}...")

        rule_result = rule_engine.analyze_text(text)
        ml_result   = ml_engine.analyze_text(text)
        upi_result  = upi_engine.analyze_upi(text)
        url_result  = {"score": 0, "reasons": [], "is_trusted": False, "domain": ""}

        final = calculate_risk(
            rule_result, ml_result, url_result, upi_result,
            input_type="upi"
        )

        logger.info(
            f"UPI Result: score={final['risk_score']} "
            f"category={final['category']}"
        )

        return AnalysisResponse(
            is_scam=final["is_scam"],
            risk_score=final["risk_score"],
            threat_level=final["threat_level"],
            category=final["category"],
            reasons=final["reasons"],
            advice=final["advice"],
            score_breakdown=ScoreBreakdown(
                rule_engine=final["score_breakdown"]["rule_engine"],
                ml_engine=final["score_breakdown"]["ml_engine"],
                url_engine=final["score_breakdown"]["url_engine"],
                upi_engine=final["score_breakdown"]["upi_engine"],
            ),
            ml_probability=final["ml_probability"],
        )

    except Exception as e:
        logger.error(f"Error analyzing UPI text: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze/all", response_model=AnalysisResponse, tags=["Analysis"])
def analyze_all(request: FullAnalysisRequest):
    """
    Analyze both text and URL together in one request.
    Use this when you have both a message body and a URL to check.
    """
    try:
        if not request.text and not request.url:
            raise HTTPException(
                status_code=400,
                detail="Provide at least one of: text, url"
            )

        text = request.text or ""
        url  = request.url or ""

        rule_result = rule_engine.analyze_text(text or url)
        ml_result   = ml_engine.analyze_text(text or url)
        upi_result  = upi_engine.analyze_upi(text)
        url_result  = url_engine.analyze_url(url) if url else \
                      {"score": 0, "reasons": [], "is_trusted": False, "domain": ""}

        final = calculate_risk(
            rule_result, ml_result, url_result, upi_result,
            input_type="text"
        )

        return AnalysisResponse(
            is_scam=final["is_scam"],
            risk_score=final["risk_score"],
            threat_level=final["threat_level"],
            category=final["category"],
            reasons=final["reasons"],
            advice=final["advice"],
            score_breakdown=ScoreBreakdown(
                rule_engine=final["score_breakdown"]["rule_engine"],
                ml_engine=final["score_breakdown"]["ml_engine"],
                url_engine=final["score_breakdown"]["url_engine"],
                upi_engine=final["score_breakdown"]["upi_engine"],
            ),
            ml_probability=final["ml_probability"],
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in analyze/all: {e}")
        raise HTTPException(status_code=500, detail=str(e))
