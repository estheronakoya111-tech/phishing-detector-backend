from fastapi import FastAPI, Request, HTTPException
from analyzer import analyze_message
from url_extractor import extract_urls
from risk_assessment import assess_risk
from models import AnalysisResult, AnalysisRequest
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware



limiter = Limiter(key_func=get_remote_address)

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000",
                    "http://127.0.0.1:3000"],
    
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.state.limiter = limiter
@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests. Please try again later."}
    )
@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": "An unexpected error occurred. Please try again later."}
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