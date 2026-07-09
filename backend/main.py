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
from dotenv import load_dotenv
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import urlopen
from typing import Optional, Dict, List, Any
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ============================================
# LOAD .env FILE
# ============================================
load_dotenv(Path(__file__).resolve().parent / ".env")

# ============================================
# API KEYS
# ============================================
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
BREVO_API_KEY = os.getenv("BREVO_API_KEY", "")
APP_VERSION = os.getenv("APP_VERSION", "2.0.0")

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

from fastapi import FastAPI, HTTPException, Response, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("⚠️ python-whois not installed")

# ============================================
# DATABASE, AUTH AND SECURITY IMPORTS
# ============================================
from database import get_db
from auth import router as auth_router
from security import verify_api_key, generate_api_key
from models import User, PredictionHistory, PredictionModelResult

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
    version=APP_VERSION,
)

cors_origins = [
    origin.strip()
    for origin in os.getenv("CORS_ORIGINS", "*").split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    return response

# ============================================
# ROUTER REGISTRATION
# ============================================
app.include_router(auth_router)
app.include_router(auth_router, prefix="/auth")

# ============================================
# MODEL LOADING
# ============================================
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
MODEL_DIR = os.path.join(PROJECT_ROOT, "model")
FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")

if os.path.isdir(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
    app.mount("/css", StaticFiles(directory=os.path.join(FRONTEND_DIR, "css")), name="css")
    app.mount("/js", StaticFiles(directory=os.path.join(FRONTEND_DIR, "js")), name="js")

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
# LOAD TRAINED FEATURE COLUMNS FROM METRICS
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
# URL VALIDATION FUNCTION
# ============================================
def validate_url(url: str):
    """
    Validate URL format before prediction.
    """
    if not url:
        raise HTTPException(
            status_code=400,
            detail="URL is required."
        )

    if len(url) > 2048:
        raise HTTPException(status_code=400, detail="URL is too long.")

    if any(char.isspace() for char in url):
        raise HTTPException(status_code=400, detail="URL cannot contain whitespace.")
    
    parsed = urlparse(url)
    
    if parsed.scheme not in ["http", "https"]:
        raise HTTPException(
            status_code=400,
            detail="Only HTTP and HTTPS URLs are allowed."
        )
    
    if not parsed.netloc:
        raise HTTPException(
            status_code=400,
            detail="Invalid URL."
        )

    if parsed.username or parsed.password:
        raise HTTPException(status_code=400, detail="URLs with embedded credentials are not allowed.")

    try:
        parsed.port
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid URL port.")

    host = parsed.hostname or ""
    if not host or len(host) > 253:
        raise HTTPException(status_code=400, detail="Invalid hostname.")

    try:
        host.encode("idna").decode("ascii")
    except UnicodeError:
        raise HTTPException(status_code=400, detail="Invalid hostname.")

    if host.endswith(".") or ".." in host:
        raise HTTPException(status_code=400, detail="Invalid hostname.")

    if not re.match(r"^[A-Za-z0-9.-]+$", host):
        raise HTTPException(status_code=400, detail="Invalid hostname.")
    
    return parsed

# ============================================
# SSRF PROTECTION FUNCTION
# ============================================
def block_ssrf(parsed):
    """
    Block localhost and private/internal IPs to prevent SSRF attacks.
    """
    host = parsed.hostname

    if not host:
        raise HTTPException(
            status_code=400,
            detail="Invalid hostname."
        )

    host_lower = host.lower().strip(".")

    if host_lower in {"localhost", "localhost.localdomain"} or host_lower.endswith(".local"):
        raise HTTPException(
            status_code=403,
            detail="Internal hostnames are not allowed."
        )

    try:
        direct_ip = ipaddress.ip_address(host_lower)
        if (
            direct_ip.is_private
            or direct_ip.is_loopback
            or direct_ip.is_link_local
            or direct_ip.is_reserved
            or direct_ip.is_multicast
            or direct_ip.is_unspecified
        ):
            raise HTTPException(
                status_code=403,
                detail="Private/Internal IPs are not allowed."
            )
    except ValueError:
        pass

    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise HTTPException(
                status_code=403,
                detail="Private/Internal IPs are not allowed."
            )

    except ValueError:
        pass
    except socket.gaierror:
        pass

# ============================================
# BASIC RATE LIMITING
# ============================================

RATE_LIMIT = 100          # requests
RATE_WINDOW = 3600        # seconds (1 hour)

request_log = defaultdict(list)


def check_rate_limit(api_key_hash: str):
    """
    Basic per-API-key rate limiting.
    """

    now = time.time()

    # Remove old requests
    request_log[api_key_hash] = [
        t for t in request_log[api_key_hash]
        if now - t < RATE_WINDOW
    ]

    if len(request_log[api_key_hash]) >= RATE_LIMIT:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Try again later."
        )

    request_log[api_key_hash].append(now)

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
    execution_time: float

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
    model_results: Dict[str, ModelResult] = Field(default_factory=dict)
    virustotal: dict = Field(default_factory=dict)
    threat_intel: dict = Field(default_factory=dict)
    ai_agent: dict = Field(default_factory=dict)
    usage_count: Optional[int] = None

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
    url = url.strip()
    if url.startswith("//"):
        raise HTTPException(status_code=400, detail="URL scheme is required.")
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
    risk_summary = "Low risk"
    if prediction == "malicious":
        risk_summary = "High risk - block or investigate before visiting."
    elif prediction == "suspicious":
        risk_summary = "Medium risk - review carefully before trusting this URL."

    human_readable = (
        f"This URL was classified as {prediction}. "
        f"The main signals were: {', '.join(risk_factors[:4])}."
    )

    return {
        "explanation": explanation,
        "risk_summary": risk_summary,
        "human_readable": human_readable,
        "confidence_note": "Confidence is based on majority voting across loaded ML models plus URL, domain, and rule-engine signals.",
        "mitre_attack": ["TA0001 Initial Access", "T1566 Phishing"] if prediction in {"malicious", "suspicious"} else [],
        "owasp_mapping": ["SSRF protection", "Untrusted URL input validation"],
        "incident_response": [
            "Do not visit the URL or enter credentials.",
            "Capture the URL, timestamp, and affected user context.",
            "Block the domain at DNS or proxy controls if confirmed malicious.",
        ] if prediction in {"malicious", "suspicious"} else ["Continue monitoring and keep browser and endpoint protections enabled."],
        "recommendations": [
            "Verify the destination through an independent trusted channel.",
            "Use a password manager to detect lookalike domains.",
            "Report suspicious links to the security team.",
        ],
        "source": "rule-based",
    }

# ============================================
# THREAT INTELLIGENCE
# ============================================
def check_virustotal(domain: str) -> Dict:
    if not VIRUSTOTAL_API_KEY:
        return {
            "domain": domain,
            "status": "no_key",
            "reputation": "Unavailable",
            "detection_count": 0,
            "community_score": 0,
            "scan_results": [],
            "error": "VirusTotal API key not configured",
        }
    
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected
            scan_results = [
                {"category": key, "count": value}
                for key, value in stats.items()
            ]
            
            return {
                "domain": domain,
                "status": "analyzed",
                "malicious_votes": malicious,
                "total_engines": total,
                "detection_count": malicious + suspicious,
                "detection_ratio": f"{malicious}/{total}",
                "reputation": attributes.get("reputation", 0),
                "community_score": attributes.get("reputation", 0),
                "scan_results": scan_results,
            }
        elif response.status_code == 404:
            return {
                "domain": domain,
                "status": "not_found",
                "reputation": "Unknown",
                "detection_count": 0,
                "community_score": 0,
                "scan_results": [],
                "error": "Domain not found",
            }
        else:
            return {
                "domain": domain,
                "status": "error",
                "reputation": "Unavailable",
                "detection_count": 0,
                "community_score": 0,
                "scan_results": [],
                "error": f"API error: {response.status_code}",
            }
    except Exception as e:
        return {
            "domain": domain,
            "status": "error",
            "reputation": "Unavailable",
            "detection_count": 0,
            "community_score": 0,
            "scan_results": [],
            "error": str(e),
        }

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
    
    feed_hit = bool(threat_feeds)
    return {
        "virustotal": vt_result,
        "abuseipdb": {
            "source": "local reputation proxy",
            "listed": feed_hit,
            "confidence_score": 90 if feed_hit else 0,
        },
        "openphish": {
            "source": "local phishing feed proxy",
            "listed": feed_hit,
            "matches": threat_feeds,
        },
        "urlhaus": {
            "source": "local malware feed proxy",
            "listed": any("malware" in item.lower() for item in threat_feeds),
            "matches": threat_feeds,
        },
        "threat_feeds": threat_feeds,
        "comparison": comparison,
        "threat_comparison": comparison,
    }

# ============================================
# API ENDPOINTS
# ============================================
def health_payload(db: Session | None = None):
    database_status = "not_checked"
    if db is not None:
        try:
            db.execute(text("SELECT 1"))
            database_status = "ok"
        except Exception as exc:
            database_status = f"error: {exc.__class__.__name__}"

    return {
        "status": "ok",
        "version": APP_VERSION,
        "backend_version": APP_VERSION,
        "database": database_status,
        "loaded_ml_models": [name for name, model in models.items() if model is not None],
        "services": {
            "virustotal": "configured" if VIRUSTOTAL_API_KEY else "not_configured",
            "openai": "configured" if OPENAI_API_KEY else "not_configured",
            "gemini": "configured" if GEMINI_API_KEY else "not_configured",
            "brevo": "configured" if BREVO_API_KEY else "not_configured",
        },
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

@app.get("/index.html")
def frontend_index():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return health_payload()

@app.get("/dashboard.html")
def frontend_dashboard():
    dashboard_path = os.path.join(FRONTEND_DIR, "dashboard.html")
    if os.path.exists(dashboard_path):
        return FileResponse(dashboard_path)
    return health_payload()

@app.head("/")
def frontend_head():
    return Response(status_code=200)

@app.get("/api/health")
@app.get("/health")
def health(db: Session = Depends(get_db)):
    return health_payload(db)

@app.get("/favicon.ico")
def favicon():
    return Response(status_code=204)

@app.post("/predict")
def predict(
    req: PredictRequest,
    api_key: str = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    # ===== STEP 1: Check Rate Limit =====
    check_rate_limit(api_key)
    
    # ===== STEP 2: Normalize URL =====
    url = _normalize_url(req.url.strip())
    
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    
    # ===== STEP 3: Validate URL Format =====
    parsed = validate_url(url)
    
    # ===== STEP 4: Block SSRF (Private/Internal IPs) =====
    block_ssrf(parsed)
    
    # ===== STEP 5: Check Model Availability =====
    if not models:
        raise HTTPException(status_code=503, detail="No ML models are available")
    
    # Get domain from validated URL
    domain = parsed.hostname or ''
    
    # ===== 6. DNS Check =====
    domain_exists = _domain_exists(domain) if domain else False
    print(f"🔍 Domain '{domain}' exists: {domain_exists}")
    
    # ===== 7. Feature Extraction =====
    feats = extract_features(url)
    print(f"📊 Extracted features for: {url}")
    
    # ===== 8. Domain Age =====
    domain_age = None
    if domain_exists:
        domain_age = _domain_age_days(url, check_exists=True)
    feats["domain_age_days"] = domain_age
    print(f"📅 Domain age: {domain_age} days" if domain_age else "📅 Domain age: N/A")
    
    # ===== 9. Rule Engine =====
    is_malicious, rule_confidence, rule_reason = check_phishing_patterns(url, domain)
    rule_override = False
    
    if is_malicious:
        rule_override = True
        print(f"🔥 RULE-BASED OVERRIDE: {rule_reason} ({rule_confidence:.2%})")
    
    # ===== 10. Prepare Features for ML =====
    if FEATURE_COLUMNS:
        try:
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
    
    # ===== 11. ML Predictions (all models in parallel) =====
    def run_model(model_name: str, model: Any) -> tuple[str, dict]:
        start = time.perf_counter()
        if model is None:
            return model_name, {
                "prediction": "safe",
                "confidence": 0.0,
                "execution_time": round(time.perf_counter() - start, 4),
                "error": "Model file not loaded",
            }

        try:
            proba = model.predict_proba(X)[0]
            pred_idx = int(np.argmax(proba))
            confidence = float(proba[pred_idx])

            if hasattr(label_encoder, "classes_"):
                prediction = str(label_encoder.classes_[pred_idx])
            else:
                prediction = ["safe", "suspicious", "malicious"][pred_idx]

            elapsed = round(time.perf_counter() - start, 4)
            print(f"  ✅ {model_name}: {prediction} ({confidence:.2%}) in {elapsed}s")
            return model_name, {
                "prediction": prediction,
                "confidence": round(confidence, 4),
                "execution_time": elapsed,
            }
        except Exception as e:
            elapsed = round(time.perf_counter() - start, 4)
            print(f"  ❌ {model_name} failed: {e}")
            return model_name, {
                "prediction": "safe",
                "confidence": 0.0,
                "execution_time": elapsed,
                "error": str(e),
            }

    model_results = {}
    with ThreadPoolExecutor(max_workers=max(1, len(MODEL_FILES))) as executor:
        futures = [
            executor.submit(run_model, model_name, models.get(model_name))
            for model_name in MODEL_FILES
        ]
        for future in as_completed(futures):
            model_name, result = future.result()
            model_results[model_name] = result

    model_results = {
        model_name: model_results[model_name]
        for model_name in MODEL_FILES
        if model_name in model_results
    }
    ml_predictions = [result["prediction"] for result in model_results.values()]
    ml_confidences = [result["confidence"] for result in model_results.values()]
    
    # ===== 12. Final Decision =====
    vote_counts = {}
    for pred in ml_predictions:
        vote_counts[pred] = vote_counts.get(pred, 0) + 1

    severity_rank = {"malicious": 3, "suspicious": 2, "safe": 1}
    final_prediction = sorted(
        vote_counts.items(),
        key=lambda item: (item[1], severity_rank.get(item[0], 0)),
        reverse=True,
    )[0][0]

    agreeing_confs = [
        ml_confidences[i]
        for i, p in enumerate(ml_predictions)
        if p == final_prediction
    ]
    final_confidence = sum(agreeing_confs) / len(agreeing_confs) if agreeing_confs else 0.0

    print(f"📊 FINAL: {final_prediction} (ML Majority Voting, {final_confidence:.2%})")
    
    # ===== 13. Build Risk Factors =====
    risk_factors = _build_risk_factors(feats, domain_exists, rule_reason if rule_override else "")
    risk_level = _risk_level(final_prediction, final_confidence)
    
    # ===== 14. Feature Summary =====
    feature_summary = {k: feats.get(k) for k in FEATURE_COLUMNS if k in feats} if FEATURE_COLUMNS else feats
    feature_summary["domain_exists"] = domain_exists
    feature_summary["domain_age_days"] = domain_age
    feature_summary["rule_override"] = rule_override
    
    # ===== 15. AI Agent =====
    ai_agent = generate_ai_agent_explanation(
        url, risk_factors, final_prediction, domain_age, domain_exists, rule_override
    )
    
    # ============================================================
    # ===== 16. Threat Intelligence (FIXED) =====
    # ============================================================
    threat_intel = None
    virustotal_data = None
    
    if req.use_threat_intel and domain:
        # Try to get threat intelligence even if domain doesn't exist
        threat_intel = get_threat_intelligence(domain)
        virustotal_data = threat_intel.get("virustotal") if threat_intel else None
        
        # If domain doesn't exist, override with appropriate message
        if not domain_exists:
            threat_intel["virustotal"]["status"] = "domain_not_found"
            threat_intel["virustotal"]["error"] = "Domain does not exist - cannot check VirusTotal"
            threat_intel["comparison"] = "❌ Domain not found"
            threat_intel["threat_comparison"] = "❌ Domain not found"
    else:
        # Threat intel disabled
        threat_intel = {
            "virustotal": {
                "domain": domain,
                "status": "disabled",
                "reputation": "Not requested",
                "detection_count": 0,
                "community_score": 0,
                "scan_results": [],
            },
            "abuseipdb": {"listed": False, "confidence_score": 0},
            "openphish": {"listed": False, "matches": []},
            "urlhaus": {"listed": False, "matches": []},
            "threat_feeds": [],
            "comparison": "Threat intelligence disabled for this request",
            "threat_comparison": "Threat intelligence disabled for this request",
        }
        virustotal_data = threat_intel.get("virustotal") if threat_intel else None
    
    # ===== 17. Update Usage Counter =====
    user = None
    usage_count = None
    try:
        user = db.query(User).filter(User.api_key_hash == api_key).first()
        if user:
            user.usage_count += 1
            db.commit()
            usage_count = user.usage_count
            print(f"📊 Updated usage count for user {user.email}: {usage_count}")
    except Exception as e:
        print(f"⚠️ Failed to update usage count: {e}")
    
    # ============================================================
    # ===== 18. Save Prediction History (One Record Per Analysis) =====
    # ============================================================
    try:
        if user:
            # Calculate risk score (0-100)
            risk_score = 0
            if final_prediction == "malicious":
                risk_score = 80 + int(final_confidence * 20)
            elif final_prediction == "suspicious":
                risk_score = 40 + int(final_confidence * 30)
            else:
                risk_score = int((1 - final_confidence) * 30)
            risk_score = min(100, max(0, risk_score))
            
            # Calculate scan duration
            scan_duration = sum(r.get("execution_time", 0) for r in model_results.values())
            
            # Create one history record with all fields
            history = PredictionHistory(
                user_id=user.id,
                url=url,
                prediction=final_prediction,
                confidence=round(final_confidence, 4),
                risk_level=risk_level,
                ai_agent=json.dumps(ai_agent),
                virustotal=json.dumps(virustotal_data) if virustotal_data else None,
                threat_intelligence=json.dumps(threat_intel) if threat_intel else None,
                feature_summary=json.dumps(feature_summary),
                domain_age=domain_age,
                domain_exists=domain_exists,
                rule_override=rule_override,
                risk_factors=json.dumps(risk_factors),
                risk_score=risk_score,
                scan_duration=round(scan_duration, 4),
            )

            db.add(history)
            db.commit()
            db.refresh(history)

            print(f"✅ History Created ID: {history.id} for user {user.email}")

            # ===== Save individual model results =====
            for model_name, result in model_results.items():
                model_result = PredictionModelResult(
                    history_id=history.id,
                    model_name=model_name,
                    prediction=result["prediction"],
                    confidence=result["confidence"],
                    execution_time=result.get("execution_time", 0.0),
                    feature_summary=json.dumps(feature_summary),
                    domain_age=domain_age,
                    domain_exists=domain_exists,
                    rule_override=rule_override,
                    risk_factors=json.dumps(risk_factors),
                )
                db.add(model_result)
            
            db.commit()
            print(f"✅ Model results saved for history ID: {history.id}")

    except Exception as e:
        print("❌ History Save Error:", e)
        db.rollback()
    
    # ===== 19. Response =====
    if not isinstance(ai_agent, dict):
        ai_agent = {}
    if not isinstance(threat_intel, dict):
        threat_intel = {
            "virustotal": {},
            "abuseipdb": {},
            "openphish": {},
            "urlhaus": {},
            "threat_feeds": [],
            "comparison": "Threat intelligence unavailable",
            "threat_comparison": "Threat intelligence unavailable",
        }
    if not isinstance(virustotal_data, dict):
        virustotal_data = threat_intel.get("virustotal", {})

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
        virustotal=virustotal_data,
        threat_intel=threat_intel,
        usage_count=usage_count
    )

# ============================================
# DASHBOARD API
# ============================================
def _loads_json(value: Optional[str], fallback: Any):
    if not value:
        return fallback
    try:
        return json.loads(value)
    except Exception:
        return fallback


def _history_summary(item: PredictionHistory) -> dict:
    return {
        "id": item.id,
        "url": item.url,
        "prediction": item.prediction,
        "confidence": item.confidence,
        "risk_level": item.risk_level,
        "domain_age": item.domain_age,
        "domain_exists": item.domain_exists,
        "rule_override": item.rule_override,
        "risk_score": item.risk_score,
        "risk_factors": _loads_json(item.risk_factors, []),
        "created_at": item.created_at,
    }


def _history_detail(item: PredictionHistory, db: Session) -> dict:
    model_rows = (
        db.query(PredictionModelResult)
        .filter(PredictionModelResult.history_id == item.id)
        .order_by(PredictionModelResult.id.asc())
        .all()
    )

    return {
        **_history_summary(item),
        "final_result": item.prediction,
        "ai_agent": _loads_json(item.ai_agent, {}),
        "virustotal": _loads_json(item.virustotal, {}),
        "threat_intel": _loads_json(item.threat_intelligence, {}),
        "feature_summary": _loads_json(item.feature_summary, {}),
        "features": _loads_json(item.feature_summary, {}),
        "risk_factors": _loads_json(item.risk_factors, []),
        "domain_age": item.domain_age,
        "risk_score": item.risk_score,
        "scan_duration": item.scan_duration,
        "rule_engine": {
            "rule_override": item.rule_override,
            "risk_level": item.risk_level,
        },
        "model_results": {
            row.model_name: {
                "prediction": row.prediction,
                "confidence": row.confidence,
                "execution_time": row.execution_time or 0.0,
            }
            for row in model_rows
        },
    }


@app.get("/dashboard")
def dashboard(
    api_key: str = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(
        User.api_key_hash == api_key
    ).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    history = (
        db.query(PredictionHistory)
        .filter(PredictionHistory.user_id == user.id)
        .order_by(PredictionHistory.created_at.desc())
        .all()
    )

    counts = {"safe": 0, "suspicious": 0, "malicious": 0}
    for item in history:
        if item.prediction in counts:
            counts[item.prediction] += 1

    return {
        "email": user.email,
        "api_key_prefix": user.api_key_prefix,
        "usage_count": user.usage_count,
        "total_requests": len(history),
        "safe_urls": counts["safe"],
        "suspicious_urls": counts["suspicious"],
        "malicious_urls": counts["malicious"],
        "recent_activity": [_history_summary(item) for item in history[:5]],
        "created_at": user.created_at,
        "last_login": user.last_login,
        "email_verified": user.email_verified,
        "is_active": user.is_active,
    }


@app.get("/recent-requests")
def recent_requests(
    api_key: str = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(
        User.api_key_hash == api_key
    ).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    history = (
        db.query(PredictionHistory)
        .filter(PredictionHistory.user_id == user.id)
        .order_by(PredictionHistory.created_at.desc())
        .limit(10)
        .all()
    )

    return [_history_summary(item) for item in history]


@app.get("/history/{history_id}")
def history_detail(
    history_id: int,
    api_key: str = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(
        User.api_key_hash == api_key
    ).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    item = (
        db.query(PredictionHistory)
        .filter(
            PredictionHistory.id == history_id,
            PredictionHistory.user_id == user.id,
        )
        .first()
    )

    if not item:
        raise HTTPException(status_code=404, detail="History item not found")

    return _history_detail(item, db)


@app.post("/regenerate-key")
def regenerate_api_key(
    api_key: str = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(
        User.api_key_hash == api_key
    ).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    raw_key, key_hash, key_prefix = generate_api_key()

    user.api_key_hash = key_hash
    user.api_key_prefix = key_prefix
    user.api_key_created_at = datetime.utcnow()

    db.commit()

    return {
        "message": "API Key regenerated successfully",
        "api_key": raw_key
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
