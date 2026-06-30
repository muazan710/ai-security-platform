"""
FastAPI backend for AI Security Intelligence Platform.

Run with:
    uvicorn main:app --reload --port 8000

Endpoints:
    GET  /            -> health check
    POST /predict      -> URL risk prediction with explainability
"""
import sys, os, json, time
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "model"))

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from features import extract_features, FEATURE_COLUMNS

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "model")

app = FastAPI(
    title="AI Security Intelligence Platform API",
    description="Detects suspicious/malicious URLs and explains why.",
    version="1.0.0",
)

# CORS so the frontend (different port) can call this API.
# For production, restrict allow_origins to your actual frontend domain.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# --- Load model artifacts once at startup ---
model = joblib.load(os.path.join(MODEL_DIR, "best_model.joblib"))
label_encoder = joblib.load(os.path.join(MODEL_DIR, "label_encoder.joblib"))
with open(os.path.join(MODEL_DIR, "metrics.json")) as f:
    METRICS = json.load(f)

# Simple in-memory rate limiter (per-process) - basic API abuse mitigation.
# For real deployment use Redis-backed limiter / API gateway throttling.
_RATE_WINDOW_SECONDS = 60
_RATE_MAX_REQUESTS = 60
_request_log = {}


class PredictRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048, description="URL to analyze")


class PredictResponse(BaseModel):
    url: str
    prediction: str
    confidence: float
    risk_level: str
    risk_factors: list[str]
    feature_summary: dict


def _basic_rate_limit(client_key: str = "global"):
    now = time.time()
    bucket = _request_log.setdefault(client_key, [])
    # drop old entries
    while bucket and now - bucket[0] > _RATE_WINDOW_SECONDS:
        bucket.pop(0)
    if len(bucket) >= _RATE_MAX_REQUESTS:
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again later.")
    bucket.append(now)


def _risk_level(prediction: str, confidence: float) -> str:
    if prediction == "malicious":
        return "HIGH"
    if prediction == "suspicious":
        return "MEDIUM"
    if confidence < 0.6:
        return "MEDIUM"
    return "LOW"


def _build_risk_factors(feats: dict) -> list[str]:
    reasons = []
    if feats["is_ip_url"]:
        reasons.append("URL uses raw IP address instead of domain name")
    if feats["tld_suspicious"]:
        reasons.append(f"Suspicious top-level domain (.{feats['tld']})")
    if feats["subdomain_count"] >= 3:
        reasons.append("Excessive subdomain usage")
    if feats["num_suspicious_keywords"] > 0:
        kws = ", ".join(feats["_keyword_hits"])
        reasons.append(f"Contains suspicious keyword(s): {kws}")
    if not feats["has_https"]:
        reasons.append("No HTTPS / insecure connection")
    if feats["is_shortened_url"]:
        reasons.append("Uses a known URL shortening service (hides real destination)")
    if feats["url_length"] > 75:
        reasons.append("Unusually long URL")
    if feats["has_at_symbol"]:
        reasons.append("Contains '@' symbol (can hide real destination)")
    if feats["entropy"] > 4.0:
        reasons.append("High randomness in domain name (possible auto-generated domain)")
    if feats["num_special_chars"] >= 6:
        reasons.append("Excessive special characters in URL")
    if not reasons:
        reasons.append("No major red flags detected; standard domain structure")
    return reasons


@app.get("/")
def health():
    return {
        "status": "ok",
        "model": METRICS["best_model"],
        "classes": METRICS["classes"],
        "metrics": METRICS["results"][METRICS["best_model"]],
    }


@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest):
    _basic_rate_limit()

    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    feats = extract_features(url)
    X = pd.DataFrame([{k: feats[k] for k in FEATURE_COLUMNS}])

    proba = model.predict_proba(X)[0]
    pred_idx = int(np.argmax(proba))
    prediction = label_encoder.classes_[pred_idx]
    confidence = float(proba[pred_idx])

    risk_factors = _build_risk_factors(feats)

    # --- Consistency safeguard ---
    # The ML model is trained on a finite dataset, so it can occasionally
    # mis-rank a brand-new/unseen domain it has never seen patterns for.
    # We avoid showing a confusing "malicious/HIGH" verdict when the
    # explainability layer found ZERO actual red flags - in that case we
    # trust the rule-based evidence over a low-confidence model guess.
    no_red_flags = risk_factors == ["No major red flags detected; standard domain structure"]
    if no_red_flags and prediction != "safe" and confidence < 0.65:
        prediction = "safe"
        confidence = round(1 - confidence, 4)

    risk_level = _risk_level(prediction, confidence)

    return PredictResponse(
        url=url,
        prediction=prediction,
        confidence=round(confidence, 4),
        risk_level=risk_level,
        risk_factors=risk_factors,
        feature_summary={k: feats[k] for k in FEATURE_COLUMNS},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
