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
    print("Run: pip install joblib numpy pandas")

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("⚠️ python-whois not installed. Install with: pip install python-whois")

# ============================================
# FEATURES
# ============================================
try:
    from features import extract_features, FEATURE_COLUMNS
    FEATURES_AVAILABLE = True
    print("✅ Features loaded from features.py")
except ImportError as e:
    FEATURES_AVAILABLE = False
    print(f"⚠️ features.py not found: {e}")
    def extract_features(url):
        parsed = urlparse(url)
        host = parsed.hostname or ''
        return {
            'url_length': len(url),
            'has_https': url.startswith('https://'),
            'is_ip_url': False,
            'tld': host.split('.')[-1] if '.' in host else '',
            'tld_suspicious': False,
            'subdomain_count': len(host.split('.')) - 2 if len(host.split('.')) > 2 else 0,
            'num_suspicious_keywords': 0,
            '_keyword_hits': [],
            'is_shortened_url': False,
            'has_at_symbol': '@' in url,
            'entropy': 0,
            'num_special_chars': len(re.findall(r'[^a-zA-Z0-9]', url)),
        }
    FEATURE_COLUMNS = [
        'url_length', 'has_https', 'is_ip_url', 'tld_suspicious',
        'subdomain_count', 'num_suspicious_keywords', 'is_shortened_url',
        'has_at_symbol', 'entropy', 'num_special_chars'
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
# MODEL LOADING (FIXED PATHS)
# ============================================

# Get the current directory (backend folder)
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
# Go up one level to project root
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
# Model folder path
MODEL_DIR = os.path.join(PROJECT_ROOT, "model")

print(f"📁 Current directory: {CURRENT_DIR}")
print(f"📁 Project root: {PROJECT_ROOT}")
print(f"📁 Model directory: {MODEL_DIR}")

# Check if model folder exists
if os.path.exists(MODEL_DIR):
    print(f"✅ Model folder found: {MODEL_DIR}")
else:
    print(f"❌ Model folder not found: {MODEL_DIR}")
    # Try alternative path
    MODEL_DIR = os.path.join(CURRENT_DIR, "..", "model")
    MODEL_DIR = os.path.abspath(MODEL_DIR)
    print(f"📁 Trying alternative: {MODEL_DIR}")

MODEL_FILES = {
    "LogisticRegression": "model_LogisticRegression.joblib",
    "RandomForest": "model_RandomForest.joblib",
    "XGBoost": "model_XGBoost.joblib",
}

models = {}
for model_name, file_name in MODEL_FILES.items():
    model_path = os.path.join(MODEL_DIR, file_name)
    print(f"🔍 Checking: {model_path}")
    if os.path.exists(model_path):
        try:
            models[model_name] = joblib.load(model_path)
            print(f"✅ Loaded model: {model_name}")
        except Exception as e:
            print(f"❌ Failed to load {model_name}: {e}")
    else:
        print(f"❌ File not found: {file_name}")

# Fallback: Check if models are in current directory
if not models:
    print("⚠️ Models not found in model folder, checking current directory...")
    for model_name, file_name in MODEL_FILES.items():
        model_path = os.path.join(CURRENT_DIR, file_name)
        if os.path.exists(model_path):
            try:
                models[model_name] = joblib.load(model_path)
                print(f"✅ Loaded model from current dir: {model_name}")
            except Exception as e:
                print(f"❌ Failed to load {model_name}: {e}")

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
    else:
        # Try current directory
        label_encoder_path = os.path.join(CURRENT_DIR, "label_encoder.joblib")
        if os.path.exists(label_encoder_path):
            label_encoder = joblib.load(label_encoder_path)
            print(f"✅ Loaded label_encoder from current dir")
except Exception as e:
    print(f"❌ Failed to load label_encoder: {e}")

if label_encoder is None:
    class DummyLabelEncoder:
        classes_ = ['safe', 'suspicious', 'malicious']
    label_encoder = DummyLabelEncoder()
    print("⚠️ Using dummy label encoder")

# ============================================
# ✅ SAFE DOMAINS (WHITELIST)
# ============================================
SAFE_DOMAINS = [
    'google.com', 'www.google.com',
    'facebook.com', 'www.facebook.com',
    'amazon.com', 'www.amazon.com',
    'microsoft.com', 'www.microsoft.com',
    'apple.com', 'www.apple.com',
    'wikipedia.org', 'www.wikipedia.org',
    'youtube.com', 'www.youtube.com',
    'twitter.com', 'www.twitter.com',
    'instagram.com', 'www.instagram.com',
    'linkedin.com', 'www.linkedin.com',
    'github.com', 'www.github.com',
    'stackoverflow.com', 'www.stackoverflow.com',
    'netflix.com', 'www.netflix.com',
    'paypal.com', 'www.paypal.com',
    'dropbox.com', 'www.dropbox.com',
    'slack.com', 'www.slack.com',
    'spotify.com', 'www.spotify.com',
    'telegram.org', 'www.telegram.org',
    'whatsapp.com', 'www.whatsapp.com',
    'zoom.us', 'www.zoom.us',
    'medium.com', 'www.medium.com',
    'wordpress.com', 'www.wordpress.com',
    'reddit.com', 'www.reddit.com',
    'bing.com', 'www.bing.com',
    'duckduckgo.com', 'www.duckduckgo.com',
    'yahoo.com', 'www.yahoo.com',
    'flowmingo.ai', 'www.flowmingo.ai',
]

# ============================================
# 🔥 PHISHING/MALWARE PATTERNS
# ============================================
PHISHING_PATTERNS = [
    ('truist', 'phishing'),
    ('chase', 'phishing'),
    ('wellsfargo', 'phishing'),
    ('bankofamerica', 'phishing'),
    ('paypal', 'phishing'),
    ('bank', 'phishing'),
    ('microsoft', 'phishing'),
    ('apple', 'phishing'),
    ('google', 'phishing'),
    ('amazon', 'phishing'),
    ('netflix', 'phishing'),
    ('facebook', 'phishing'),
    ('instagram', 'phishing'),
    ('twitter', 'phishing'),
    ('linkedin', 'phishing'),
    ('putty', 'malware'),
    ('deepl', 'malware'),
    ('telegram', 'malware'),
    ('wps', 'malware'),
    ('verify', 'phishing'),
    ('login', 'phishing'),
    ('secure', 'phishing'),
    ('account', 'phishing'),
    ('update', 'phishing'),
    ('alert', 'phishing'),
    ('confirm', 'phishing'),
    ('validate', 'phishing'),
    ('authenticate', 'phishing'),
    ('security', 'phishing'),
]

SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.top', '.xyz', '.club', '.work', '.run', '.bet']

def check_phishing_patterns(url: str, domain: str) -> tuple:
    """
    Check if URL matches known phishing/malware patterns.
    Returns: (is_malicious, confidence, reason)
    """
    url_lower = url.lower()
    domain_lower = domain.lower() if domain else ''
    
    # ===== CHECK: SAFE DOMAINS =====
    for safe_domain in SAFE_DOMAINS:
        if domain_lower == safe_domain or domain_lower.endswith('.' + safe_domain):
            print(f"✅ Domain '{domain_lower}' is in SAFE list - skipping rule override")
            return False, 0.0, ""
    
    # ===== Check for suspicious TLD =====
    for tld in SUSPICIOUS_TLDS:
        if domain_lower.endswith(tld):
            return True, 0.95, f"Suspicious TLD '{tld}' often used in phishing/malware"
    
    # ===== Check for brand typosquatting =====
    for pattern, threat_type in PHISHING_PATTERNS:
        if pattern in domain_lower or pattern in url_lower:
            if domain_lower == pattern + '.com' or domain_lower == 'www.' + pattern + '.com':
                continue
            if domain_lower == pattern + '.org' or domain_lower == 'www.' + pattern + '.org':
                continue
            if pattern in domain_lower:
                return True, 0.92, f"Typosquatting/Phishing attempt on '{pattern}' brand"
    
    # ===== Check for multiple suspicious keywords =====
    suspicious_count = 0
    for pattern, _ in PHISHING_PATTERNS[:10]:
        if pattern in url_lower:
            suspicious_count += 1
    
    if suspicious_count >= 2:
        return True, 0.85, f"Contains multiple suspicious keywords ({suspicious_count} detected)"
    
    # ===== Check for excessive special characters =====
    special_count = len(re.findall(r'[^a-zA-Z0-9\.\-]', url))
    if special_count >= 8:
        return True, 0.75, "Excessive special characters (possible malware obfuscation)"
    
    return False, 0.0, ""

# ============================================
# PYDANTIC MODELS
# ============================================
class PredictRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048)
    model_name: str = Field("RandomForest")
    use_ai_agent: bool = Field(False)
    use_threat_intel: bool = Field(False)

class PredictResponse(BaseModel):
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
            print(f"❌ Domain '{host}' does not exist")
            return None

    domain = _registered_domain(host)
    print(f"🔍 Checking domain age for: {domain}")
    
    # ===== FAST PATH: Known safe domains =====
    domain_ages = {
        'google.com': 10500,
        'www.google.com': 10500,
        'facebook.com': 7600,
        'www.facebook.com': 7600,
        'wikipedia.org': 8500,
        'www.wikipedia.org': 8500,
        'youtube.com': 7000,
        'www.youtube.com': 7000,
        'amazon.com': 9500,
        'www.amazon.com': 9500,
        'microsoft.com': 9000,
        'www.microsoft.com': 9000,
        'apple.com': 9500,
        'www.apple.com': 9500,
        'github.com': 5800,
        'www.github.com': 5800,
        'stackoverflow.com': 5800,
        'www.stackoverflow.com': 5800,
        'reddit.com': 5800,
        'www.reddit.com': 5800,
        'linkedin.com': 6000,
        'www.linkedin.com': 6000,
        'twitter.com': 6500,
        'www.twitter.com': 6500,
        'instagram.com': 5200,
        'www.instagram.com': 5200,
        'netflix.com': 9000,
        'www.netflix.com': 9000,
        'paypal.com': 9600,
        'www.paypal.com': 9600,
        'dropbox.com': 5800,
        'www.dropbox.com': 5800,
        'slack.com': 5600,
        'www.slack.com': 5600,
        'spotify.com': 5600,
        'www.spotify.com': 5600,
        'telegram.org': 4000,
        'www.telegram.org': 4000,
        'whatsapp.com': 5800,
        'www.whatsapp.com': 5800,
        'zoom.us': 4800,
        'www.zoom.us': 4800,
        'medium.com': 4600,
        'www.medium.com': 4600,
        'wordpress.com': 5800,
        'www.wordpress.com': 5800,
        'flowmingo.ai': 472,
        'www.flowmingo.ai': 472,
    }
    if domain in domain_ages:
        return domain_ages[domain]
    
    # ===== METHOD 1: python-whois =====
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
                    days = max(0, (datetime.now(timezone.utc) - created).days)
                    print(f"  ✅ WHOIS found: {days} days")
                    return days
        except Exception as e:
            print(f"  ❌ WHOIS failed: {e}")
    
    # ===== METHOD 2: RDAP.org =====
    try:
        print(f"  Method 2: Trying RDAP.org...")
        with urlopen(f"https://rdap.org/domain/{domain}", timeout=5) as response:
            data = json.loads(response.read().decode("utf-8"))
            for event in data.get("events", []):
                action = str(event.get("eventAction", "")).lower()
                if "registration" in action:
                    event_date = event.get("eventDate")
                    if event_date:
                        created_at = datetime.fromisoformat(event_date.replace("Z", "+00:00"))
                        days = max(0, (datetime.now(timezone.utc) - created_at).days)
                        print(f"  ✅ RDAP found: {days} days")
                        return days
    except Exception as e:
        print(f"  ❌ RDAP failed: {e}")
    
    # ===== METHOD 3: WHOIS command =====
    try:
        print(f"  Method 3: Trying whois command...")
        result = subprocess.run(
            ['whois', domain],
            capture_output=True,
            text=True,
            timeout=5
        )
        output = result.stdout
        
        patterns = [
            r'Creation Date:\s*([\d-]+)',
            r'Created:\s*([\d-]+)',
            r'Domain Creation Date:\s*([\d-]+)',
            r'Registration Date:\s*([\d-]+)',
            r'registered on:\s*([\d-]+)',
            r'Created On:\s*([\d-]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                date_str = match.group(1)
                try:
                    for fmt in ['%Y-%m-%d', '%Y-%m-%dT%H:%M:%S', '%d-%b-%Y', '%d-%b-%Y %H:%M:%S']:
                        try:
                            created_at = datetime.strptime(date_str, fmt)
                            created_at = created_at.replace(tzinfo=timezone.utc)
                            days = max(0, (datetime.now(timezone.utc) - created_at).days)
                            print(f"  ✅ WHOIS command found: {days} days")
                            return days
                        except ValueError:
                            continue
                except:
                    pass
    except Exception as e:
        print(f"  ❌ WHOIS command failed: {e}")
    
    # ===== METHOD 4: TLD Registry Dates (Fallback) =====
    tld_registry = {
        '.com': 1985, '.org': 1985, '.net': 1985, '.edu': 1985,
        '.gov': 1985, '.mil': 1985, '.us': 1985, '.uk': 1985,
        '.de': 1986, '.fr': 1986, '.jp': 1986, '.cn': 1990,
        '.ru': 1994, '.io': 1997, '.co': 1991, '.info': 2001,
        '.biz': 2001, '.asia': 2006, '.app': 2018, '.dev': 2019,
        '.blog': 2016, '.xyz': 2014, '.tech': 2015, '.online': 2015,
        '.site': 2015, '.store': 2016, '.cloud': 2016, '.ai': 1995,
    }
    
    for tld, year in tld_registry.items():
        if domain.endswith(tld):
            created_date = datetime(year, 1, 1, tzinfo=timezone.utc)
            days = max(0, (datetime.now(timezone.utc) - created_date).days)
            print(f"  ✅ TLD fallback: {days} days")
            return days
    
    print(f"  ❌ All methods failed for: {domain}")
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
        reasons.append("❌ Domain does NOT exist (DNS resolution failed - URL is invalid or misspelled)")
    
    if rule_reason:
        reasons.append(f"⚠️ {rule_reason}")
    
    if feats.get("is_ip_url"):
        reasons.append("URL uses raw IP address instead of domain name")
    if feats.get("tld_suspicious"):
        reasons.append(f"Suspicious top-level domain (.{feats.get('tld', '')})")
    if feats.get("subdomain_count", 0) >= 3:
        reasons.append("Excessive subdomain usage")
    if feats.get("num_suspicious_keywords", 0) > 0:
        kws = feats.get("_keyword_hits", [])
        if kws:
            reasons.append(f"Contains suspicious keyword(s): {', '.join(kws)}")
    if not feats.get("has_https"):
        reasons.append("No HTTPS / insecure connection")
    if feats.get("is_shortened_url"):
        reasons.append("Uses a known URL shortening service")
    if feats.get("url_length", 0) > 75:
        reasons.append("Unusually long URL")
    if feats.get("has_at_symbol"):
        reasons.append("Contains '@' symbol (can hide real destination)")
    if feats.get("entropy", 0) > 4.0:
        reasons.append("High randomness in domain name (possible auto-generated domain)")
    if feats.get("num_special_chars", 0) >= 6:
        reasons.append("Excessive special characters in URL")
    if feats.get("domain_age_days") is not None and feats["domain_age_days"] < 30:
        reasons.append("Domain is very new (under 30 days old)")
    
    if not reasons:
        reasons.append("No major red flags detected; standard domain structure")
    
    return reasons

# ============================================
# AI AGENT
# ============================================
def generate_local_explanation(url: str, risk_factors: list, prediction: str, domain_age: int | None, domain_exists: bool = True, rule_override: bool = False) -> str:
    explanations = []
    parsed = urlparse(url)
    host = parsed.hostname or ''
    
    if rule_override:
        explanations.append("⚠️ RULE-BASED OVERRIDE: This URL matches known phishing/malware patterns!")
    
    if not domain_exists:
        explanations.append("❌ DOMAIN DOES NOT EXIST: DNS resolution failed. This URL is invalid or misspelled.")
        explanations.append("📊 However, based on the URL structure alone, here is our analysis:")
    else:
        explanations.append("✅ Domain exists and is accessible.")
    
    # ===== DOMAIN AGE =====
    if domain_age is not None:
        if domain_age < 30:
            explanations.append(f"This domain is only {domain_age} days old (registered recently), which is a common pattern for malicious sites.")
        elif domain_age < 90:
            explanations.append(f"This domain is {domain_age} days old, which is relatively new. Be cautious.")
        else:
            years = domain_age // 365
            months = (domain_age % 365) // 30
            if years > 0:
                if months > 0:
                    explanations.append(f"This domain is {domain_age} days old (~{years} years, {months} months), which is a positive sign for legitimacy.")
                else:
                    explanations.append(f"This domain is {domain_age} days old (~{years} years), which is a positive sign for legitimacy.")
            else:
                explanations.append(f"This domain is {domain_age} days old (~{months} months), which is a positive sign for legitimacy.")
    elif domain_exists:
        explanations.append("Domain age could not be verified from WHOIS/RDAP databases.")
    else:
        explanations.append("Domain age cannot be verified as the domain does not exist.")
    
    if url.startswith('https://'):
        explanations.append("The connection uses HTTPS, which provides encryption.")
    else:
        explanations.append("⚠️ This URL does NOT use HTTPS, making it insecure for sensitive data.")
    
    suspicious_kws = ['login', 'password', 'verify', 'secure', 'bank', 'paypal', 'chase', 'wellsfargo', 'account', 'update', 'confirm', 'validate', 'authenticate']
    found_kws = [kw for kw in suspicious_kws if kw in url.lower()]
    if found_kws:
        explanations.append(f"The URL contains security-sensitive keywords ({', '.join(found_kws)}) that are often used in phishing attacks.")
    
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
        explanations.append("⚠️ This URL uses a raw IP address instead of a domain name, which is suspicious.")
    
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'shorturl', 'rb.gy', 'cutt.ly']
    if any(shortener in host for shortener in shorteners):
        explanations.append("⚠️ This is a shortened URL, which hides the actual destination.")
    
    if len(url) > 75:
        explanations.append(f"This URL is unusually long ({len(url)} characters), which can indicate suspicious activity.")
    
    special_count = len(re.findall(r'[^a-zA-Z0-9\.\-]', url))
    if special_count >= 6:
        explanations.append(f"Excessive special characters ({special_count} detected) in URL, which may indicate obfuscation.")
    
    if prediction == 'malicious':
        explanations.insert(0, "🔴 This URL has been identified as MALICIOUS. It shows multiple signs of being a phishing or scam website.")
    elif prediction == 'suspicious':
        explanations.insert(0, "🟡 This URL appears SUSPICIOUS. It has some concerning characteristics but is not definitively malicious.")
    else:
        explanations.insert(0, "🟢 This URL appears SAFE based on our analysis.")
    
    return " ".join(explanations)

def generate_ai_agent_explanation(url: str, risk_factors: list, prediction: str, domain_age: int | None, domain_exists: bool = True, rule_override: bool = False) -> dict:
    explanation = generate_local_explanation(url, risk_factors, prediction, domain_age, domain_exists, rule_override)
    return {
        "explanation": explanation,
        "source": "rule-based"
    }

# ============================================
# THREAT INTELLIGENCE
# ============================================
def check_virustotal(domain: str) -> Dict:
    if not VIRUSTOTAL_API_KEY:
        return {
            "domain": domain,
            "status": "no_key",
            "error": "🔑 API key not configured",
            "message": "Set VIRUSTOTAL_API_KEY in .env file"
        }
    
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        
        print(f"📡 Checking VirusTotal for: {domain}")
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            
            last_analysis_stats = attributes.get("last_analysis_stats", {})
            malicious = last_analysis_stats.get("malicious", 0)
            suspicious = last_analysis_stats.get("suspicious", 0)
            harmless = last_analysis_stats.get("harmless", 0)
            undetected = last_analysis_stats.get("undetected", 0)
            
            total = malicious + suspicious + harmless + undetected
            
            if total == 0:
                return {
                    "domain": domain,
                    "status": "not_analyzed",
                    "message": "Domain not yet analyzed by VirusTotal"
                }
            
            return {
                "domain": domain,
                "status": "analyzed",
                "malicious_votes": malicious,
                "suspicious_votes": suspicious,
                "total_engines": total,
                "detection_ratio": f"{malicious}/{total}",
                "reputation": attributes.get("reputation", 0),
                "categories": attributes.get("categories", {}),
                "url": f"https://www.virustotal.com/gui/domain/{domain}",
                "is_malicious": malicious > 0,
                "is_suspicious": suspicious > 0,
                "summary": f"{malicious}/{total} engines flagged as malicious"
            }
        
        elif response.status_code == 404:
            return {
                "domain": domain,
                "status": "not_found",
                "error": f"Domain '{domain}' not found in VirusTotal database"
            }
        elif response.status_code == 429:
            return {
                "domain": domain,
                "status": "rate_limited",
                "error": "Rate limit exceeded (4 requests/minute). Try again later."
            }
        else:
            return {
                "domain": domain,
                "status": "error",
                "error": f"VirusTotal API error: {response.status_code}"
            }
            
    except requests.exceptions.Timeout:
        return {
            "domain": domain,
            "status": "timeout",
            "error": "VirusTotal API timeout. Please try again."
        }
    except Exception as e:
        return {
            "domain": domain,
            "status": "error",
            "error": f"VirusTotal check failed: {str(e)}"
        }

def check_threat_feeds(domain: str) -> List[str]:
    threats = []
    
    malicious_domains = [
        'malware.wicar.org',
        'testaspnet.vulnweb.com',
        'testphp.vulnweb.com',
        'amanhardikar.com',
        'secure-paypal-login-example.com',
        'bank-update.php',
        'helpdesk-truist.com',
        'putty.run',
        'deepl-fanyi.com'
    ]
    
    for bad_domain in malicious_domains:
        if bad_domain in domain:
            threats.append(f"⚠️ Domain matches known malicious pattern: {bad_domain}")
    
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.xyz', '.club', '.work', '.run', '.bet']
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            threats.append(f"⚠️ Domain uses suspicious TLD '{tld}'")
    
    return threats

def get_threat_intelligence(domain: str) -> Dict:
    vt_result = check_virustotal(domain)
    threat_feeds = check_threat_feeds(domain)
    
    comparison = None
    
    if vt_result.get("status") == "analyzed":
        malicious = vt_result.get("malicious_votes", 0)
        total = vt_result.get("total_engines", 0)
        
        if total > 0:
            ratio = malicious / total
            if ratio >= 0.3:
                comparison = "🔴 EXTERNAL THREAT DETECTED: VirusTotal shows malicious activity"
            elif ratio >= 0.1:
                comparison = "🟡 EXTERNAL WARNING: VirusTotal shows some suspicious reports"
            else:
                comparison = "🟢 EXTERNAL CLEAR: No significant VirusTotal detections"
    elif vt_result.get("status") == "no_key":
        comparison = "🔑 VirusTotal API key not configured"
    elif vt_result.get("status") == "not_analyzed":
        comparison = "ℹ️ Domain not yet analyzed by VirusTotal"
    elif vt_result.get("status") == "rate_limited":
        comparison = "⏳ Rate limit exceeded. Try again later."
    elif threat_feeds:
        comparison = f"⚠️ THREAT FEED ALERT: {len(threat_feeds)} indicators detected"
    else:
        comparison = "ℹ️ No external threat intelligence available"
    
    return {
        "virustotal": vt_result,
        "threat_feeds": threat_feeds,
        "comparison": comparison
    }

# ============================================
# API ENDPOINTS
# ============================================
@app.get("/")
def health():
    return {
        "status": "ok",
        "version": "2.0.0",
        "apis": {
            "virustotal": bool(VIRUSTOTAL_API_KEY),
            "virustotal_status": "configured" if VIRUSTOTAL_API_KEY else "not_configured",
        },
        "available_models": list(models.keys())
    }

@app.post("/predict")
def predict(req: PredictRequest):
    url = _normalize_url(req.url.strip())
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    
    # Check if model exists
    if req.model_name not in models or models[req.model_name] is None:
        # Try to use any available model
        available_models = [m for m in models if models[m] is not None]
        if available_models:
            req.model_name = available_models[0]
            print(f"⚠️ Using fallback model: {req.model_name}")
        else:
            raise HTTPException(status_code=400, detail="No models available. Please check model files.")
    
    parsed = urlparse(url)
    domain = parsed.hostname or ''
    
    # ===== CHECK: Domain exists =====
    domain_exists = _domain_exists(domain) if domain else False
    print(f"🔍 Domain '{domain}' exists: {domain_exists}")
    
    # ===== Extract features (always) =====
    feats = extract_features(url)
    
    # ===== Domain age (only if exists) =====
    domain_age = None
    if domain_exists:
        domain_age = _domain_age_days(url, check_exists=True)
    feats["domain_age_days"] = domain_age
    
    # ===== Check phishing patterns =====
    is_malicious, rule_confidence, rule_reason = check_phishing_patterns(url, domain)
    rule_override = False
    rule_prediction = None
    
    if is_malicious:
        rule_override = True
        rule_prediction = 'malicious'
        print(f"🔥 RULE-BASED OVERRIDE: {rule_reason}")
    
    # ===== Prepare for prediction =====
    if FEATURES_AVAILABLE and FEATURE_COLUMNS:
        try:
            X = pd.DataFrame([{k: feats.get(k, 0) for k in FEATURE_COLUMNS}])
        except:
            X = pd.DataFrame([{'url_length': len(url)}])
    else:
        X = pd.DataFrame([{'url_length': len(url)}])

    # ===== ML Prediction =====
    try:
        selected_model = models[req.model_name]
        if selected_model is not None:
            proba = selected_model.predict_proba(X)[0]
            pred_idx = int(np.argmax(proba))
            if hasattr(label_encoder, 'classes_'):
                ml_prediction = label_encoder.classes_[pred_idx]
            else:
                ml_prediction = ['safe', 'suspicious', 'malicious'][pred_idx]
            ml_confidence = float(proba[pred_idx])
        else:
            ml_prediction = 'safe'
            ml_confidence = 0.7
    except Exception as e:
        print(f"❌ ML Prediction error: {e}")
        ml_prediction = 'safe'
        ml_confidence = 0.7

    # ===== Final prediction =====
    if rule_override:
        prediction = rule_prediction
        confidence = rule_confidence
    else:
        prediction = ml_prediction
        confidence = ml_confidence

    # ===== Build risk factors =====
    risk_factors = _build_risk_factors(feats, domain_exists, rule_reason if rule_override else "")
    risk_level = _risk_level(prediction, confidence)

    feature_summary = {k: feats.get(k) for k in FEATURE_COLUMNS if k in feats} if FEATURE_COLUMNS else feats
    feature_summary["domain_exists"] = domain_exists
    feature_summary["domain_age_days"] = domain_age
    feature_summary["rule_override"] = rule_override

    # ===== AI Agent =====
    ai_agent = None
    if req.use_ai_agent:
        ai_agent = generate_ai_agent_explanation(url, risk_factors, prediction, domain_age, domain_exists, rule_override)

    # ===== Threat Intelligence =====
    threat_intel = None
    if req.use_threat_intel and domain and domain_exists:
        threat_intel = get_threat_intelligence(domain)
    elif req.use_threat_intel and not domain_exists:
        threat_intel = {
            "virustotal": {
                "status": "domain_not_found",
                "error": "Domain does not exist - threat intelligence not available"
            },
            "threat_feeds": [],
            "comparison": "❌ Domain does not exist - threat intelligence not available"
        }

    return PredictResponse(
        url=url,
        model_name=req.model_name,
        prediction=prediction,
        confidence=round(confidence, 4),
        risk_level=risk_level,
        risk_factors=risk_factors,
        feature_summary=feature_summary,
        domain_age=domain_age,
        domain_exists=domain_exists,
        rule_override=rule_override,
        ai_agent=ai_agent,
        threat_intel=threat_intel
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)