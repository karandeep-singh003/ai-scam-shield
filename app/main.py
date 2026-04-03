from fastapi import FastAPI

app = FastAPI(
    title="AI Scam Shield",
    description="AI-powered detection for social engineering, phishing, SMS and UPI scams",
    version="1.0.0"
)

@app.get("/health")
def health_check():
    return {"status": "ok", "message": "AI Scam Shield is running"}
