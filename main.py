import os
import uvicorn
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from analyzer import analyze_message
from url_extractor import extract_urls
from risk_assessment import assess_risk
from models import AnalysisResult, AnalysisRequest

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="Phishing Detector API")

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.state.limiter = limiter

# Health Check Route for Pxxl Deployment Verification
@app.get("/")
def health_check():
    return {"status": "ok", "message": "Phishing Detector API is live"}

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests. Please try again later."}
    )

@app.post("/analyze")
@limiter.limit("10/minute")
def analyze(request: Request, data: AnalysisRequest):
    try:
        urls, url_results = extract_urls(data.message)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))

    message = data.message

    for url in urls:
        message = message.replace(url, "")

    message_findings, message_score = analyze_message(message)

    risk_level, all_findings, recommendation = assess_risk(
        message_score,
        message_findings,
        url_results
    )

    return AnalysisResult(
        risk_level=risk_level,
        findings=all_findings,
        urls=url_results,
        recommendation=recommendation
    )

# CRITICAL FOR PXXL DEPLOYMENT:
# Binds to 0.0.0.0 and dynamically reads the PORT assigned by Pxxl
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)