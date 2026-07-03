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

# Feature columns used by the model
FEATURE_COLUMNS = [
    'url_length',
    'has_https',
    'is_ip_url',
    'tld_suspicious',
    'subdomain_count',
    'num_suspicious_keywords',
    'is_shortened_url',
    'has_at_symbol',
    'entropy',
    'num_special_chars',
    'tld',
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
    query = parsed.query or ''
    
    # Basic features
    features = {
        'url_length': len(url),
        'has_https': url.startswith('https://'),
        'is_ip_url': _is_ip_address(host),
        'tld': _get_tld(host),
        'tld_suspicious': False,
        'subdomain_count': _count_subdomains(host),
        'num_suspicious_keywords': 0,
        '_keyword_hits': [],
        'is_shortened_url': _is_shortened(url),
        'has_at_symbol': '@' in url,
        'entropy': _calculate_entropy(host),
        'num_special_chars': _count_special_chars(url),
        'domain_age_days': None,
    }
    
    # Check TLD suspiciousness
    if features['tld'] in SUSPICIOUS_TLDS:
        features['tld_suspicious'] = True
    
    # Check for suspicious keywords
    keyword_hits = []
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url.lower():
            keyword_hits.append(keyword)
    features['_keyword_hits'] = keyword_hits
    features['num_suspicious_keywords'] = len(keyword_hits)
    
    return features


def _is_ip_address(host: str) -> bool:
    """Check if host is an IP address"""
    if not host:
        return False
    # IPv4 pattern
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
    # Remove www prefix if present
    if host.startswith('www.'):
        host = host[4:]
    parts = host.split('.')
    # Remove TLD (last part)
    if len(parts) >= 2:
        parts = parts[:-1]
    # The last part is the domain name, rest are subdomains
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
    
    # Remove common prefixes
    host_clean = host
    if host_clean.startswith('www.'):
        host_clean = host_clean[4:]
    
    # Calculate character frequency
    freq = {}
    for char in host_clean:
        freq[char] = freq.get(char, 0) + 1
    
    length = len(host_clean)
    if length == 0:
        return 0.0
    
    # Shannon entropy
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    
    return entropy


def _count_special_chars(url: str) -> int:
    """Count number of special characters in URL (non-alphanumeric)"""
    return len(re.findall(r'[^a-zA-Z0-9]', url))


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


# ✅ NEW: Function for train.py
def extract_feature_vector(url: str) -> dict:
    """
    Extract feature vector for model input.
    Returns only the feature columns used by the model.
    """
    features = extract_features(url)
    return {k: features.get(k, 0) for k in FEATURE_COLUMNS}


# Test function
if __name__ == "__main__":
    # Test URLs
    test_urls = [
        "https://www.google.com",
        "https://secure-paypal-login-example.com",
        "http://192.168.1.1",
        "https://bit.ly/3xKj9Lm",
        "https://newstartup-launch.io",
    ]
    
    for url in test_urls:
        features = extract_features(url)
        print(f"\nURL: {url}")
        print("Features:")
        for key, value in features.items():
            if not key.startswith('_'):
                print(f"  {key}: {value}")
        print("-" * 40)
    
    # ✅ Test extract_feature_vector
    print("\n" + "=" * 60)
    print("Testing extract_feature_vector():")
    print("=" * 60)
    for url in test_urls[:2]:
        vector = extract_feature_vector(url)
        print(f"\nURL: {url}")
        print(f"Feature Vector: {vector}")