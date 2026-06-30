"""
URL Feature Extraction Module
Shared by training pipeline (notebooks/training) and the FastAPI backend,
so train/serve feature logic never drifts apart.
"""

import re
import math
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "bank", "account", "signin",
    "confirm", "password", "billing", "webscr", "paypal", "wallet",
    "support", "security", "alert", "suspend"
]

SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "info", "click", "loan", "work"}

IP_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def _safe_parse(url: str):
    if "://" not in url:
        url = "http://" + url
    try:
        return urlparse(url)
    except Exception:
        return urlparse("http://invalid")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def extract_features(url: str) -> dict:
    url = url.strip()
    parsed = _safe_parse(url)
    host = parsed.netloc.split(":")[0].split("@")[-1]  # strip userinfo/port
    host_no_www = host[4:] if host.startswith("www.") else host
    path = parsed.path or ""
    full = url.lower()

    labels = host_no_www.split(".") if host_no_www else []
    tld = labels[-1].lower() if len(labels) >= 1 else ""
    # subdomain count = number of labels before domain.tld (domain+tld = last 2 labels)
    subdomain_count = max(0, len(labels) - 2)

    is_ip = bool(IP_REGEX.match(host_no_www))
    is_shortener = host_no_www.lower() in SHORTENER_DOMAINS
    suspicious_tld = tld in SUSPICIOUS_TLDS

    keyword_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full]

    special_chars = sum(full.count(c) for c in ["-", "_", "@", "%", "=", "&", "?"])

    features = {
        # --- URL features ---
        "url_length": len(url),
        "num_dots": full.count("."),
        "num_hyphens": full.count("-"),
        "num_special_chars": special_chars,
        "has_https": int(parsed.scheme == "https"),
        "has_at_symbol": int("@" in url),
        "digit_ratio": (sum(c.isdigit() for c in url) / len(url)) if url else 0.0,
        "entropy": round(shannon_entropy(host_no_www), 3),
        "num_suspicious_keywords": len(keyword_hits),
        "path_length": len(path),

        # --- Domain features ---
        "subdomain_count": subdomain_count,
        "domain_length": len(host_no_www),
        "tld_suspicious": int(suspicious_tld),
        "tld": tld,

        # --- Security features ---
        "is_ip_url": int(is_ip),
        "is_shortened_url": int(is_shortener),
        "has_port": int(parsed.port is not None) if hasattr(parsed, "port") else 0,
        "redirect_count_proxy": full.count("//") - 1,  # crude proxy w/o live network
    }

    # Keep human-readable reasons alongside numeric features (used by API/explainability)
    features["_keyword_hits"] = keyword_hits
    return features


FEATURE_COLUMNS = [
    "url_length", "num_dots", "num_hyphens", "num_special_chars", "has_https",
    "has_at_symbol", "digit_ratio", "entropy", "num_suspicious_keywords",
    "path_length", "subdomain_count", "domain_length", "tld_suspicious",
    "is_ip_url", "is_shortened_url", "has_port", "redirect_count_proxy",
]


def extract_feature_vector(url: str) -> dict:
    """Returns only the numeric columns used directly by the ML model."""
    feats = extract_features(url)
    return {k: feats[k] for k in FEATURE_COLUMNS}
