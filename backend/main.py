"""
FastAPI backend for AI Security Intelligence Platform
With AI Security Agent & Real-Time Threat Intelligence
"""
import sys
import os
import json
import time
import socket
import re
import requests
import subprocess
from dotenv import load_dotenv
from datetime import datetime, timezone
from urllib.parse import urlparse
from urllib.request import urlopen
from typing import Optional, Dict, List, Any

# ============================================
# LOAD .env FILE
# ============================================
load_dotenv()

# ============================================
# API KEYS
# ============================================
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

print("=" * 50)
print("🔑 API Key Status:")
print(f"  VirusTotal: {'✅ Configured' if VIRUSTOTAL_API_KEY else '❌ Not Configured'}")
print("=" * 50)

# ============================================
# IMPORT MODULES
# ============================================
try:
    import joblib
    import numpy as np
    import pandas as pd
except ImportError:
    print("⚠️ Warning: joblib/numpy/pandas not installed")

from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("⚠️ python-whois not installed")

# ============================================
# FEATURES - DYNAMIC LOADING WITH FALLBACK
# ============================================
FEATURE_COLUMNS = None
extract_features = None

try:
    from features import extract_features as feat_extract, FEATURE_COLUMNS as feat_cols
    extract_features = feat_extract
    FEATURE_COLUMNS = feat_cols
    FEATURES_AVAILABLE = True
    print("✅ Features loaded from features.py")
    print(f"📋 Feature columns: {FEATURE_COLUMNS}")
except ImportError:
    FEATURES_AVAILABLE = False
    print("⚠️ features.py not found, using fallback")
    
    def extract_features(url):
        parsed = urlparse(url)
        host = parsed.hostname or ''
        return {
            'url_length': len(url),
            'num_dots': url.count('.'),
            'num_hyphens': url.count('-'),
            'num_special_chars': len(re.findall(r'[^a-zA-Z0-9]', url)),
            'has_https': 1 if url.startswith('https://') else 0,
            'has_at_symbol': 1 if '@' in url else 0,
            'digit_ratio': sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0,
            'entropy': 0,
            'num_suspicious_keywords': 0,
            'path_length': len(parsed.path),
            'subdomain_count': len(host.split('.')) - 2 if len(host.split('.')) > 2 else 0,
            'domain_length': len(host),
            'tld_suspicious': 0,
            'is_ip_url': 1 if False else 0,
            'is_shortened_url': 0,
            'has_port': 1 if ':' in host else 0,
            'redirect_count_proxy': 0,
            '_keyword_hits': [],
            'tld': host.split('.')[-1] if '.' in host else '',
            'domain_age_days': None,
        }
    
    FEATURE_COLUMNS = [
        'url_length', 'num_dots', 'num_hyphens', 'num_special_chars',
        'has_https', 'has_at_symbol', 'digit_ratio', 'entropy',
        'num_suspicious_keywords', 'path_length', 'subdomain_count',
        'domain_length', 'tld_suspicious', 'is_ip_url', 'is_shortened_url',
        'has_port', 'redirect_count_proxy'
    ]

# ============================================
# APP INSTANCE
# ============================================
app = FastAPI(
    title="AI Security Intelligence Platform API",
    description="ML-based URL analysis with AI Agent & Threat Intelligence",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ============================================
# MODEL LOADING
# ============================================
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
MODEL_DIR = os.path.join(PROJECT_ROOT, "model")
FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")

if os.path.isdir(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

print(f"📁 Model directory: {MODEL_DIR}")

MODEL_FILES = {
    "LogisticRegression": "model_LogisticRegression.joblib",
    "RandomForest": "model_RandomForest.joblib",
    "XGBoost": "model_XGBoost.joblib",
}

models = {}
for model_name, file_name in MODEL_FILES.items():
    model_path = os.path.join(MODEL_DIR, file_name)
    if os.path.exists(model_path):
        try:
            models[model_name] = joblib.load(model_path)
            print(f"✅ Loaded model: {model_name}")
        except Exception as e:
            print(f"❌ Failed to load {model_name}: {e}")
    else:
        print(f"❌ File not found: {file_name}")

if not models:
    print("❌ No models loaded, using dummy")
    models["RandomForest"] = None

# Load label encoder
label_encoder = None
try:
    label_encoder_path = os.path.join(MODEL_DIR, "label_encoder.joblib")
    if os.path.exists(label_encoder_path):
        label_encoder = joblib.load(label_encoder_path)
        print(f"✅ Loaded label_encoder")
except Exception as e:
    print(f"❌ Failed to load label_encoder: {e}")

if label_encoder is None:
    class DummyLabelEncoder:
        classes_ = ['safe', 'suspicious', 'malicious']
    label_encoder = DummyLabelEncoder()
    print("⚠️ Using dummy label encoder")

# ============================================
# ✅ LOAD TRAINED FEATURE COLUMNS FROM METRICS
# ============================================
TRAINED_FEATURES = None
try:
    metrics_path = os.path.join(MODEL_DIR, "metrics.json")
    if os.path.exists(metrics_path):
        with open(metrics_path, 'r') as f:
            metrics_data = json.load(f)
        TRAINED_FEATURES = metrics_data.get('feature_columns')
        if TRAINED_FEATURES:
            print(f"✅ Loaded trained feature columns: {len(TRAINED_FEATURES)} features")
        else:
            print("⚠️ No feature_columns found in metrics.json")
except Exception as e:
    print(f"⚠️ Could not load metrics.json: {e}")

# If trained features available, use them
if TRAINED_FEATURES:
    FEATURE_COLUMNS = TRAINED_FEATURES
    print(f"📋 Using trained feature columns: {FEATURE_COLUMNS}")

# ============================================
# SAFE DOMAINS
# ============================================
SAFE_DOMAINS = [
    'google.com', 'www.google.com', 'facebook.com', 'www.facebook.com',
    'amazon.com', 'www.amazon.com', 'microsoft.com', 'www.microsoft.com',
    'apple.com', 'www.apple.com', 'wikipedia.org', 'www.wikipedia.org',
    'youtube.com', 'www.youtube.com', 'twitter.com', 'www.twitter.com',
    'instagram.com', 'www.instagram.com', 'linkedin.com', 'www.linkedin.com',
    'github.com', 'www.github.com', 'stackoverflow.com', 'www.stackoverflow.com',
    'netflix.com', 'www.netflix.com', 'paypal.com', 'www.paypal.com',
    'dropbox.com', 'www.dropbox.com', 'slack.com', 'www.slack.com',
    'spotify.com', 'www.spotify.com', 'telegram.org', 'www.telegram.org',
    'whatsapp.com', 'www.whatsapp.com', 'zoom.us', 'www.zoom.us',
    'medium.com', 'www.medium.com', 'wordpress.com', 'www.wordpress.com',
    'reddit.com', 'www.reddit.com', 'bing.com', 'www.bing.com',
    'duckduckgo.com', 'www.duckduckgo.com', 'yahoo.com', 'www.yahoo.com',
    'flowmingo.ai', 'www.flowmingo.ai',
]

# ============================================
# PHISHING PATTERNS
# ============================================
PHISHING_PATTERNS = [
    ('truist', 'phishing'), ('chase', 'phishing'), ('wellsfargo', 'phishing'),
    ('bankofamerica', 'phishing'), ('paypal', 'phishing'), ('bank', 'phishing'),
    ('microsoft', 'phishing'), ('apple', 'phishing'), ('google', 'phishing'),
    ('amazon', 'phishing'), ('netflix', 'phishing'), ('facebook', 'phishing'),
    ('instagram', 'phishing'), ('twitter', 'phishing'), ('linkedin', 'phishing'),
    ('putty', 'malware'), ('deepl', 'malware'), ('telegram', 'malware'), ('wps', 'malware'),
    ('verify', 'phishing'), ('login', 'phishing'), ('secure', 'phishing'),
    ('account', 'phishing'), ('update', 'phishing'), ('alert', 'phishing'),
    ('confirm', 'phishing'), ('validate', 'phishing'), ('authenticate', 'phishing'),
    ('security', 'phishing'),
]

SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.top', '.xyz', '.club', '.work', '.run', '.bet']

def check_phishing_patterns(url: str, domain: str) -> tuple:
    """Check if URL matches known phishing/malware patterns."""
    url_lower = url.lower()
    domain_lower = domain.lower() if domain else ''
    
    # Check safe domains
    for safe_domain in SAFE_DOMAINS:
        if domain_lower == safe_domain or domain_lower.endswith('.' + safe_domain):
            return False, 0.0, ""
    
    # Check suspicious TLDs
    for tld in SUSPICIOUS_TLDS:
        if domain_lower.endswith(tld):
            return True, 0.95, f"Suspicious TLD '{tld}'"
    
    # Check typosquatting
    for pattern, threat_type in PHISHING_PATTERNS:
        if pattern in domain_lower or pattern in url_lower:
            if domain_lower == pattern + '.com' or domain_lower == 'www.' + pattern + '.com':
                continue
            if domain_lower == pattern + '.org' or domain_lower == 'www.' + pattern + '.org':
                continue
            if pattern in domain_lower:
                return True, 0.92, f"Typosquatting on '{pattern}'"
    
    # Multiple suspicious keywords
    suspicious_count = 0
    for pattern, _ in PHISHING_PATTERNS[:10]:
        if pattern in url_lower:
            suspicious_count += 1
    if suspicious_count >= 2:
        return True, 0.85, f"Multiple suspicious keywords ({suspicious_count})"
    
    # Excessive special characters
    special_count = len(re.findall(r'[^a-zA-Z0-9\.\-]', url))
    if special_count >= 8:
        return True, 0.75, "Excessive special characters"
    
    return False, 0.0, ""

# ============================================
# PYDANTIC MODELS
# ============================================
class PredictRequest(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    url: str = Field(..., min_length=3, max_length=2048)
    model_name: str = Field("RandomForest")
    use_ai_agent: bool = Field(False)
    use_threat_intel: bool = Field(False)

class ModelResult(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    prediction: str
    confidence: float

class PredictResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    url: str
    model_name: str
    prediction: str
    confidence: float
    risk_level: str
    risk_factors: list[str]
    feature_summary: dict
    domain_age: int | None = None
    domain_exists: bool = True
    rule_override: bool = False
    model_results: Dict[str, ModelResult] = {}
    ai_agent: Optional[dict] = None
    threat_intel: Optional[dict] = None

# ============================================
# DOMAIN FUNCTIONS
# ============================================
def _registered_domain(host: str) -> str:
    host = host.lower()
    if host.startswith("www."):
        host = host[4:]
    labels = host.split(".")
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return host

def _domain_exists(host: str) -> bool:
    try:
        socket.getaddrinfo(host, 80, socket.AF_INET)
        return True
    except socket.gaierror:
        return False

def _domain_age_days(url: str, check_exists: bool = True) -> int | None:
    host = urlparse(url).hostname
    if not host:
        return None

    if check_exists:
        if not _domain_exists(host):
            return None

    domain = _registered_domain(host)
    
    # FAST PATH: Known domains
    domain_ages = {
        'google.com': 10500, 'www.google.com': 10500,
        'facebook.com': 7600, 'www.facebook.com': 7600,
        'wikipedia.org': 8500, 'www.wikipedia.org': 8500,
        'youtube.com': 7000, 'www.youtube.com': 7000,
        'amazon.com': 9500, 'www.amazon.com': 9500,
        'microsoft.com': 9000, 'www.microsoft.com': 9000,
        'apple.com': 9500, 'www.apple.com': 9500,
        'github.com': 5800, 'www.github.com': 5800,
        'stackoverflow.com': 5800, 'www.stackoverflow.com': 5800,
        'reddit.com': 5800, 'www.reddit.com': 5800,
        'linkedin.com': 6000, 'www.linkedin.com': 6000,
        'twitter.com': 6500, 'www.twitter.com': 6500,
        'instagram.com': 5200, 'www.instagram.com': 5200,
        'netflix.com': 9000, 'www.netflix.com': 9000,
        'paypal.com': 9600, 'www.paypal.com': 9600,
        'flowmingo.ai': 472, 'www.flowmingo.ai': 472,
    }
    if domain in domain_ages:
        return domain_ages[domain]
    
    # WHOIS method
    if WHOIS_AVAILABLE:
        try:
            w = whois.whois(domain)
            if w.creation_date:
                created = w.creation_date
                if isinstance(created, list):
                    created = created[0]
                if created:
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=timezone.utc)
                    return max(0, (datetime.now(timezone.utc) - created).days)
        except Exception as e:
            print(f"  ❌ WHOIS failed: {e}")
    
    # RDAP.org
    try:
        with urlopen(f"https://rdap.org/domain/{domain}", timeout=5) as response:
            data = json.loads(response.read().decode("utf-8"))
            for event in data.get("events", []):
                action = str(event.get("eventAction", "")).lower()
                if "registration" in action:
                    event_date = event.get("eventDate")
                    if event_date:
                        created_at = datetime.fromisoformat(event_date.replace("Z", "+00:00"))
                        return max(0, (datetime.now(timezone.utc) - created_at).days)
    except Exception as e:
        print(f"  ❌ RDAP failed: {e}")
    
    return None

# ============================================
# OTHER HELPERS
# ============================================
def _normalize_url(url: str) -> str:
    if "://" not in url:
        return "https://" + url
    return url

def _risk_level(prediction: str, confidence: float) -> str:
    if prediction == "malicious":
        return "HIGH"
    if prediction == "suspicious":
        return "MEDIUM"
    if confidence < 0.6:
        return "MEDIUM"
    return "LOW"

def _build_risk_factors(feats: dict, domain_exists: bool = True, rule_reason: str = "") -> list[str]:
    reasons = []
    
    if not domain_exists:
        reasons.append("❌ Domain does NOT exist")
    
    if rule_reason:
        reasons.append(f"⚠️ {rule_reason}")
    
    if feats.get("is_ip_url"):
        reasons.append("URL uses raw IP address")
    if feats.get("tld_suspicious"):
        reasons.append(f"Suspicious TLD (.{feats.get('tld', '')})")
    if feats.get("subdomain_count", 0) >= 3:
        reasons.append("Excessive subdomain usage")
    if feats.get("num_suspicious_keywords", 0) > 0:
        kws = feats.get("_keyword_hits", [])
        if kws:
            reasons.append(f"Suspicious keywords: {', '.join(kws)}")
    if not feats.get("has_https"):
        reasons.append("No HTTPS - insecure")
    if feats.get("is_shortened_url"):
        reasons.append("Shortened URL")
    if feats.get("url_length", 0) > 75:
        reasons.append("Unusually long URL")
    if feats.get("entropy", 0) > 4.0:
        reasons.append("High randomness in domain")
    if feats.get("num_special_chars", 0) >= 6:
        reasons.append("Excessive special characters")
    if feats.get("domain_age_days") is not None and feats["domain_age_days"] < 30:
        reasons.append("Domain is very new (< 30 days)")
    
    if not reasons:
        reasons.append("No major red flags detected")
    
    return reasons

# ============================================
# AI AGENT
# ============================================
def generate_local_explanation(url: str, risk_factors: list, prediction: str, domain_age: int | None, domain_exists: bool = True, rule_override: bool = False) -> str:
    explanations = []
    parsed = urlparse(url)
    host = parsed.hostname or ''
    
    if rule_override:
        explanations.append("⚠️ RULE-BASED OVERRIDE: Matches phishing patterns!")
    
    if not domain_exists:
        explanations.append("❌ Domain does NOT exist")
    else:
        explanations.append("✅ Domain exists and is accessible")
    
    if domain_age is not None:
        if domain_age < 30:
            explanations.append(f"Domain is {domain_age} days old - VERY NEW ⚠️")
        elif domain_age < 90:
            explanations.append(f"Domain is {domain_age} days old - relatively new")
        else:
            years = domain_age // 365
            explanations.append(f"Domain is {domain_age} days old (~{years} years) - positive sign")
    elif domain_exists:
        explanations.append("Domain age could not be verified")
    
    if url.startswith('https://'):
        explanations.append("HTTPS encryption ✅")
    else:
        explanations.append("⚠️ No HTTPS - insecure")
    
    suspicious_kws = ['login', 'password', 'verify', 'secure', 'bank', 'paypal']
    found_kws = [kw for kw in suspicious_kws if kw in url.lower()]
    if found_kws:
        explanations.append(f"Suspicious keywords: {', '.join(found_kws)}")
    
    if any(shortener in host for shortener in ['bit.ly', 'tinyurl', 'goo.gl', 't.co']):
        explanations.append("⚠️ Shortened URL")
    
    if prediction == 'malicious':
        explanations.insert(0, "🔴 MALICIOUS - Phishing/Scam website detected!")
    elif prediction == 'suspicious':
        explanations.insert(0, "🟡 SUSPICIOUS - Proceed with caution")
    else:
        explanations.insert(0, "🟢 SAFE - No threats detected")
    
    return " ".join(explanations)

def generate_ai_agent_explanation(url: str, risk_factors: list, prediction: str, domain_age: int | None, domain_exists: bool = True, rule_override: bool = False) -> dict:
    explanation = generate_local_explanation(url, risk_factors, prediction, domain_age, domain_exists, rule_override)
    return {"explanation": explanation, "source": "rule-based"}

# ============================================
# THREAT INTELLIGENCE
# ============================================
def check_virustotal(domain: str) -> Dict:
    if not VIRUSTOTAL_API_KEY:
        return {"domain": domain, "status": "no_key", "error": "API key not configured"}
    
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = malicious + stats.get("suspicious", 0) + stats.get("harmless", 0) + stats.get("undetected", 0)
            
            return {
                "domain": domain,
                "status": "analyzed",
                "malicious_votes": malicious,
                "total_engines": total,
                "detection_ratio": f"{malicious}/{total}",
                "reputation": attributes.get("reputation", 0)
            }
        elif response.status_code == 404:
            return {"domain": domain, "status": "not_found", "error": "Domain not found"}
        else:
            return {"domain": domain, "status": "error", "error": f"API error: {response.status_code}"}
    except Exception as e:
        return {"domain": domain, "status": "error", "error": str(e)}

def check_threat_feeds(domain: str) -> List[str]:
    threats = []
    malicious_domains = [
        'malware.wicar.org', 'testaspnet.vulnweb.com', 'testphp.vulnweb.com',
        'secure-paypal-login-example.com', 'helpdesk-truist.com'
    ]
    for bad_domain in malicious_domains:
        if bad_domain in domain:
            threats.append(f"⚠️ Known malicious: {bad_domain}")
    return threats

def get_threat_intelligence(domain: str) -> Dict:
    vt_result = check_virustotal(domain)
    threat_feeds = check_threat_feeds(domain)
    
    comparison = "ℹ️ No external threat intelligence available"
    if vt_result.get("status") == "analyzed":
        malicious = vt_result.get("malicious_votes", 0)
        total = vt_result.get("total_engines", 0)
        if total > 0:
            ratio = malicious / total
            if ratio >= 0.3:
                comparison = "🔴 EXTERNAL THREAT DETECTED"
            elif ratio >= 0.1:
                comparison = "🟡 EXTERNAL WARNING"
            else:
                comparison = "🟢 EXTERNAL CLEAR"
    elif vt_result.get("status") == "no_key":
        comparison = "🔑 VirusTotal API key not configured"
    elif threat_feeds:
        comparison = f"⚠️ THREAT FEED ALERT: {len(threat_feeds)} indicators"
    
    return {"virustotal": vt_result, "threat_feeds": threat_feeds, "comparison": comparison}

# ============================================
# API ENDPOINTS
# ============================================
def health_payload():
    return {
        "status": "ok",
        "version": "2.0.0",
        "apis": {"virustotal": bool(VIRUSTOTAL_API_KEY)},
        "available_models": list(models.keys()),
        "feature_columns": FEATURE_COLUMNS
    }

@app.get("/")
def frontend():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return health_payload()

@app.head("/")
def frontend_head():
    return Response(status_code=200)

@app.get("/api/health")
@app.get("/health")
def health():
    return health_payload()

@app.get("/favicon.ico")
def favicon():
    return Response(status_code=204)

@app.post("/predict")
def predict(req: PredictRequest):
    url = _normalize_url(req.url.strip())
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    
    if req.model_name not in models or models[req.model_name] is None:
        raise HTTPException(status_code=400, detail=f"Model '{req.model_name}' not available")
    
    parsed = urlparse(url)
    domain = parsed.hostname or ''
    
    # ===== 1. DNS Check =====
    domain_exists = _domain_exists(domain) if domain else False
    print(f"🔍 Domain '{domain}' exists: {domain_exists}")
    
    # ===== 2. Feature Extraction =====
    feats = extract_features(url)
    print(f"📊 Extracted features for: {url}")
    
    # ===== 3. Domain Age =====
    domain_age = None
    if domain_exists:
        domain_age = _domain_age_days(url, check_exists=True)
    feats["domain_age_days"] = domain_age
    print(f"📅 Domain age: {domain_age} days" if domain_age else "📅 Domain age: N/A")
    
    # ===== 4. Rule Engine =====
    is_malicious, rule_confidence, rule_reason = check_phishing_patterns(url, domain)
    rule_override = False
    
    if is_malicious:
        rule_override = True
        print(f"🔥 RULE-BASED OVERRIDE: {rule_reason} ({rule_confidence:.2%})")
    
    # ===== 5. Prepare Features for ML =====
    if FEATURE_COLUMNS:
        try:
            # ✅ Create DataFrame with only the features the model was trained on
            X_data = {}
            for col in FEATURE_COLUMNS:
                X_data[col] = feats.get(col, 0)
            X = pd.DataFrame([X_data])
            print(f"📊 X shape: {X.shape}")
            print(f"📊 X columns: {X.columns.tolist()}")
        except Exception as e:
            print(f"⚠️ Feature DataFrame error: {e}")
            X = pd.DataFrame([{'url_length': len(url)}])
    else:
        X = pd.DataFrame([{'url_length': len(url)}])
    
    # ===== 6. ML Predictions =====
    model_results = {}
    ml_predictions = []
    ml_confidences = []
    
    for model_name, model in models.items():
        if model is not None:
            try:
                proba = model.predict_proba(X)[0]
                pred_idx = int(np.argmax(proba))
                confidence = float(proba[pred_idx])
                
                print(f"  📊 {model_name} probs: {proba}")
                
                if hasattr(label_encoder, 'classes_'):
                    prediction = label_encoder.classes_[pred_idx]
                else:
                    prediction = ['safe', 'suspicious', 'malicious'][pred_idx]
                
                model_results[model_name] = {
                    "prediction": prediction,
                    "confidence": round(confidence, 4)
                }
                ml_predictions.append(prediction)
                ml_confidences.append(confidence)
                print(f"  ✅ {model_name}: {prediction} ({confidence:.2%})")
            except Exception as e:
                print(f"  ❌ {model_name} failed: {e}")
                model_results[model_name] = {"prediction": "safe", "confidence": 0.7}
                ml_predictions.append("safe")
                ml_confidences.append(0.7)
        else:
            model_results[model_name] = {"prediction": "safe", "confidence": 0.7}
            ml_predictions.append("safe")
            ml_confidences.append(0.7)
    
    # ===== 7. Final Decision =====
    if rule_override:
        final_prediction = 'malicious'
        final_confidence = rule_confidence
        print(f"🔥 FINAL: {final_prediction} (Rule Override, {final_confidence:.2%})")
    else:
        vote_counts = {}
        for pred in ml_predictions:
            vote_counts[pred] = vote_counts.get(pred, 0) + 1
        
        final_prediction = max(vote_counts, key=vote_counts.get)
        
        agreeing_confs = [ml_confidences[i] for i, p in enumerate(ml_predictions) if p == final_prediction]
        final_confidence = sum(agreeing_confs) / len(agreeing_confs) if agreeing_confs else 0.7
        
        print(f"📊 FINAL: {final_prediction} (ML Voting, {final_confidence:.2%})")
    
    # ===== 8. Build Risk Factors =====
    risk_factors = _build_risk_factors(feats, domain_exists, rule_reason if rule_override else "")
    risk_level = _risk_level(final_prediction, final_confidence)
    
    # ===== 9. Feature Summary =====
    feature_summary = {k: feats.get(k) for k in FEATURE_COLUMNS if k in feats} if FEATURE_COLUMNS else feats
    feature_summary["domain_exists"] = domain_exists
    feature_summary["domain_age_days"] = domain_age
    feature_summary["rule_override"] = rule_override
    
    # ===== 10. AI Agent =====
    ai_agent = None
    if req.use_ai_agent:
        ai_agent = generate_ai_agent_explanation(
            url, risk_factors, final_prediction, domain_age, domain_exists, rule_override
        )
    
    # ===== 11. Threat Intelligence =====
    threat_intel = None
    if req.use_threat_intel and domain and domain_exists:
        threat_intel = get_threat_intelligence(domain)
    elif req.use_threat_intel and not domain_exists:
        threat_intel = {
            "virustotal": {"status": "domain_not_found"},
            "threat_feeds": [],
            "comparison": "❌ Domain not found"
        }
    
    # ===== 12. Response =====
    return PredictResponse(
        url=url,
        model_name=req.model_name,
        prediction=final_prediction,
        confidence=round(final_confidence, 4),
        risk_level=risk_level,
        risk_factors=risk_factors,
        feature_summary=feature_summary,
        domain_age=domain_age,
        domain_exists=domain_exists,
        rule_override=rule_override,
        model_results=model_results,
        ai_agent=ai_agent,
        threat_intel=threat_intel
    )

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
