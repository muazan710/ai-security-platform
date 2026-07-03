"""
Feature extraction module for URL analysis.
Extracts various features from URLs for ML model prediction.
"""
import re
import math
from urllib.parse import urlparse

# List of known URL shorteners
URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'short.link', 'shorte.st', 't.co', 'tiny.cc', 'shorturl.at',
    'tiny.one', 'rb.gy', 'cutt.ly', 'rebrand.ly', 'bitly.com',
    'shorturl.at', 'tiny.one', 'rb.gy', 'cutt.ly', 'rebrand.ly'
]

# Suspicious keywords in URLs
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'secure', 'bank', 'account', 'verify', 'update',
    'confirm', 'password', 'credential', 'paypal', 'chase', 'wellsfargo',
    'bankofamerica', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
    'instagram', 'twitter', 'gmail', 'outlook', 'office365', 'icloud',
    'payments', 'billing', 'invoice', 'statement', 'alert', 'security',
    'validate', 'authenticate', 'identity', 'verification', 'unlock'
]

# Suspicious TLDs
SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.top', '.xyz', '.club', '.work',
    '.date', '.download', '.review', '.win', '.bid', '.trade',
    '.stream', '.gq', '.click', '.link', '.men', '.loan'
]

# ============================================
# ✅ COMPLETE FEATURE COLUMNS (17 features)
# ============================================
FEATURE_COLUMNS = [
    'url_length',
    'num_dots',
    'num_hyphens',
    'num_special_chars',
    'has_https',
    'has_at_symbol',
    'digit_ratio',
    'entropy',
    'num_suspicious_keywords',
    'path_length',
    'subdomain_count',
    'domain_length',
    'tld_suspicious',
    'is_ip_url',
    'is_shortened_url',
    'has_port',
    'redirect_count_proxy',
]


def extract_features(url: str) -> dict:
    """
    Extract all features from a URL for ML prediction.
    
    Args:
        url: The URL to analyze
        
    Returns:
        dict: Feature dictionary with all extracted features
    """
    parsed = urlparse(url)
    host = parsed.hostname or ''
    path = parsed.path or ''
    
    # ===== URL Features =====
    url_length = len(url)
    num_dots = url.count('.')
    num_hyphens = url.count('-')
    num_special_chars = len(re.findall(r'[^a-zA-Z0-9]', url))
    has_https = 1 if url.startswith('https://') else 0
    has_at_symbol = 1 if '@' in url else 0
    
    # ===== Digit Ratio =====
    digit_count = sum(c.isdigit() for c in url)
    digit_ratio = digit_count / url_length if url_length > 0 else 0
    
    # ===== Entropy =====
    entropy = _calculate_entropy(host)
    
    # ===== Suspicious Keywords =====
    keyword_hits = []
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url.lower():
            keyword_hits.append(keyword)
    num_suspicious_keywords = len(keyword_hits)
    
    # ===== Path Features =====
    path_length = len(path)
    
    # ===== Domain Features =====
    subdomain_count = _count_subdomains(host)
    domain_length = len(host)
    tld = _get_tld(host)
    tld_suspicious = 1 if tld in SUSPICIOUS_TLDS else 0
    is_ip_url = 1 if _is_ip_address(host) else 0
    
    # ===== Shortened URL =====
    is_shortened_url = 1 if _is_shortened(url) else 0
    
    # ===== Port Detection =====
    has_port = 1 if ':' in host else 0
    
    # ===== Redirect Count (Proxy) =====
    redirect_count_proxy = _count_redirects(url)
    
    # ===== Additional =====
    domain_age_days = None
    
    features = {
        'url_length': url_length,
        'num_dots': num_dots,
        'num_hyphens': num_hyphens,
        'num_special_chars': num_special_chars,
        'has_https': has_https,
        'has_at_symbol': has_at_symbol,
        'digit_ratio': digit_ratio,
        'entropy': entropy,
        'num_suspicious_keywords': num_suspicious_keywords,
        'path_length': path_length,
        'subdomain_count': subdomain_count,
        'domain_length': domain_length,
        'tld_suspicious': tld_suspicious,
        'is_ip_url': is_ip_url,
        'is_shortened_url': is_shortened_url,
        'has_port': has_port,
        'redirect_count_proxy': redirect_count_proxy,
        # Extra fields for explainability
        '_keyword_hits': keyword_hits,
        'tld': tld,
        'domain_age_days': domain_age_days,
    }
    
    return features


def _is_ip_address(host: str) -> bool:
    """Check if host is an IP address"""
    if not host:
        return False
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, host):
        return True
    return False


def _get_tld(host: str) -> str:
    """Extract TLD from host"""
    if not host:
        return ''
    parts = host.split('.')
    if len(parts) > 1:
        return parts[-1] or ''
    return ''


def _count_subdomains(host: str) -> int:
    """Count number of subdomains in host"""
    if not host:
        return 0
    if host.startswith('www.'):
        host = host[4:]
    parts = host.split('.')
    if len(parts) >= 2:
        parts = parts[:-1]
    if len(parts) >= 2:
        return len(parts) - 1
    return 0


def _is_shortened(url: str) -> bool:
    """Check if URL is from a known shortening service"""
    parsed = urlparse(url)
    host = parsed.hostname or ''
    for shortener in URL_SHORTENERS:
        if shortener in host:
            return True
    return False


def _calculate_entropy(host: str) -> float:
    """Calculate entropy of host (randomness measure)"""
    if not host:
        return 0.0
    
    host_clean = host
    if host_clean.startswith('www.'):
        host_clean = host_clean[4:]
    
    freq = {}
    for char in host_clean:
        freq[char] = freq.get(char, 0) + 1
    
    length = len(host_clean)
    if length == 0:
        return 0.0
    
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    
    return entropy


def _count_special_chars(url: str) -> int:
    """Count number of special characters in URL (non-alphanumeric)"""
    return len(re.findall(r'[^a-zA-Z0-9]', url))


def _count_redirects(url: str) -> int:
    """
    Count redirects using proxy detection.
    Returns 0 (no redirects detected by default).
    """
    # Simple proxy/redirect detection based on URL patterns
    redirect_patterns = [
        'redirect', 'redir', 'go/', 'click',
        'link/', 'goto', 'out.', 'tracking'
    ]
    count = 0
    url_lower = url.lower()
    for pattern in redirect_patterns:
        if pattern in url_lower:
            count += 1
    # Cap at 3
    return min(count, 3)


def extract_all_features_for_model(url: str) -> dict:
    """
    Extract features and format them for model input.
    This function ensures all required features are present.
    """
    features = extract_features(url)
    
    # Ensure all FEATURE_COLUMNS are present
    model_features = {}
    for col in FEATURE_COLUMNS:
        model_features[col] = features.get(col, 0)
    
    return model_features


def extract_feature_vector(url: str) -> dict:
    """
    Extract feature vector for model input.
    Returns only the feature columns used by the model.
    """
    features = extract_features(url)
    return {k: features.get(k, 0) for k in FEATURE_COLUMNS}


# Test function
if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "https://secure-paypal-login-example.com",
        "http://192.168.1.1",
        "https://bit.ly/3xKj9Lm",
        "https://newstartup-launch.io",
    ]
    
    print("=" * 60)
    print("🔍 Testing Feature Extraction")
    print("=" * 60)
    
    for url in test_urls:
        features = extract_features(url)
        print(f"\n📌 URL: {url}")
        print("-" * 40)
        for key in FEATURE_COLUMNS:
            value = features.get(key, 'N/A')
            print(f"  {key}: {value}")
    
    print("\n" + "=" * 60)
    print("📊 Testing extract_feature_vector()")
    print("=" * 60)
    
    for url in test_urls[:3]:
        vector = extract_feature_vector(url)
        print(f"\n📌 URL: {url}")
        print(f"  Features: {vector}")