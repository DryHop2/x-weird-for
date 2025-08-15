import math
import re
from collections import Counter
from typing import Dict, List, Any


EXPECTED_HEADERS = {
    # Critical headers (weight: 2.0)
    "Host": 2.0,
    "User-Agent": 2.0,
    # Important Headers (weight: 1.5)
    "Accept": 1.5,
    "Accept-Encoding": 1.5,
    "Accept-Language": 1.5,
    "Connection": 1.5,
    # Common headers (weight: 1.0)
    "Content-Type": 1.0,
    "Content-Length": 1.0,
    "Referer": 1.0,
    "Cookie": 1.0,
    "Authorization": 1.0,
    "Cache-Control": 1.0,
    # Proxy/forwarding headerts (weight: 0.8)
    "X-Forwarded-For": 0.8,
    "X-Real-IP": 0.8,
    "X-Forwarded-Proto": 0.8,
}

SUSPICIOUS_UA_PATTERNS = {
    # High Severity (score: 1.0)
    r'\bcurl\b': 1.0,
    r'\bwget\b': 1.0,
    r'\bpython-requests\b': 1.0,
    r'\bscrapy\b': 1.0,
    r'\bGo-http-client\b': 1.0,
    # Medium severity (score: 0.7)
    r'\bbot\b': 0.7,
    r'\bspider\b': 0.7,
    r'\bcrawler\b': 0.7,
    r'\bscraper\b': 0.7,
    # Low severity (score: 0.4)
    r'\bJava\b': 0.4,
    r'\bRuby\b': 0.4,
    r'\bPerl\b': 0.4,
}

LEGITIMATE_UA_PATTERNS = {
    r'Mozilla/5\.0',
    r'AppleWebKit',
    r'Chrome/\d+',
    r'Safari/\d+',
    r'Firefox/\d+',
    r'Edge/\d+',
}


def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string.
    """
    if not text:
        return 0.0
    
    # Count character frequencies
    char_counts = Counter(text)
    length = len(text)

    # Calculate entropy
    entropy = 0
    for count in char_counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy


def calculate_char_diversity(text: str) -> float:
    """
    Calculate character diversity ratio.
    """
    if not text:
        return 0.0
    unique_chars = len(set(text))
    return unique_chars / len(text)


def detect_encoding_anomalies(value: str) -> float:
    """
    Detect suspicious encoding patterns.
    """
    score = 0.0

    # Check for excessive URL encoding
    url_encoded_ratio = len(re.findall(r'%[0-9A-Fa-f]{2}', value)) * 3 / max(len(value), 1)
    if url_encoded_ratio > 0.3:
        score += 0.5

    # Check for base64-like patterns
    if re.search(r'^[A-Za-z0-9+/]{20,}={0,2}$', value):
        score += 0.3

    # Check for hex strings
    if re.search(r'^[0-9a-fA-F]{16,}$', value):
        score += 0.3

    return min(score, 1.0)


def analyze_header_structure(headers: Dict[str, str]) -> Dict[str, float]:
    """
    Analyze overall header structure patterns.
    """
    features = {}

    # Header order consistency (compare to typical browser order)
    typical_order = ["Host", "User-Agent", "Accept", "Accept-Language",
                     "Accept-Encoding", "Referer", "Cookie"]
    header_keys = list(headers.keys())

    order_score = 0
    for i, header in enumerate(typical_order):
        if header in header_keys:
            actual_pos = header_keys.index(header)
            order_score += abs(i - actual_pos) / len(typical_order)

    features['header_order_deviation'] = order_score / max(len(typical_order), 1)

    # Case consistency analysis
    case_patterns = Counter()
    for key in headers.keys():
        if key.islower():
            case_patterns['lower'] += 1
        elif key.isupper():
            case_patterns['upper'] += 1
        elif key[0].isupper() and key[1:].islower():
            case_patterns['title'] += 1
        elif '-' in key and all(part[0].isupper() for part in key.split('-') if part):
            case_patterns['http_standard'] += 1
        else:
            case_patterns['mixed'] += 1

    # Most headers should be HTTP-standard case
    total_headers = sum(case_patterns.values())
    if total_headers > 0:
        features['case_consistency'] = case_patterns.get('http_standard', 0)
    else:
        features['case_consistency'] = 0

    return features


def extract_features(header_dict: Dict[str, str]) -> List[float]:
    """
    Extract comprehensive features from HTTP headers.
    """
    features = []

    # Weighted presence/absence of expected headers
    total_weight = 0
    present_weight = 0
    for header, weight in EXPECTED_HEADERS.items():
        total_weight += weight
        if header in header_dict:
            features.append(1)
            present_weight += weight
        else:
            features.append(0)

    # Add weighted completeness score
    features.append(present_weight / total_weight if total_weight > 0 else 0)

    # User-Agent analysis
    ua = header_dict.get("User-Agent", "")
    features.append(len(ua))

    # Calculate suspicion score for UA
    ua_suspicion = 0
    for pattern, severity in SUSPICIOUS_UA_PATTERNS.items():
        if re.search(pattern, ua, re.IGNORECASE):
            ua_suspicion = max(ua_suspicion, severity)
    features.append(ua_suspicion)

    # Check for legitimate browser patterns
    legitimate_score = sum(1 for pattern in LEGITIMATE_UA_PATTERNS if re.search(pattern, ua)) / len(LEGITIMATE_UA_PATTERNS)
    features.append(legitimate_score)

    # UA entropy and diversity
    features.append(calculate_entropy(ua))
    features.append(calculate_char_diversity(ua))

    # Header count and statistics
    features.append(len(header_dict))

    # Calculate header value statistics
    if header_dict:
        value_lengths = [len(v) for v in header_dict.values()]
        features.append(sum(value_lengths) / len(value_lengths))
        features.append(max(value_lengths))
        features.append(min(value_lengths))
        features.append(math.sqrt(sum((x - sum(value_lengths) / len(value_lengths)) ** 2
                                      for x in value_lengths) / len(value_lengths)))
    else:
        features.extend([0, 0, 0, 0])

    # Entropy features for all headers
    total_entropy = 0
    max_entropy = 0
    encoding_anomaly_score = 0

    for _, value in header_dict.items():
        entropy = calculate_entropy(value)
        total_entropy += entropy
        max_entropy = max(max_entropy, entropy)
        encoding_anomaly_score += detect_encoding_anomalies(value)

    features.append(total_entropy / max(len(header_dict), 1))
    features.append(max_entropy)
    features.append(encoding_anomaly_score / max(len(header_dict), 1))

    # Structural analysis features
    structural_features = analyze_header_structure(header_dict)
    features.append(structural_features['header_order_deviation'])
    features.append(structural_features['case_consistency'])

    # Specific header anomalies
    # Check for suspicious X- headers
    x_header_count = sum(1 for k in header_dict.keys() if k.startswith("X-"))
    features.append(x_header_count)

    # Check for dupliate-like headers (similar keys)
    duplicate_score = 0
    keys = list(header_dict.keys())
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            if keys[i].lower() == keys[j].lower():
                duplicate_score += 1
    features.append(duplicate_score)

    # Content-Type analysis
    content_type = header_dict.get("Content-Type", "")
    suspicious_mime_types = ["application/x-evil", "text/hack", "application/x-shellcode"] # FIXME
    features.append(1 if any(mime in content_type for mime in suspicious_mime_types) else 0)

    # Check for header injection attempts
    injection_patterns = [r'\r\n]', r'%0[dD]%0[aA]', r'%0[aA]', r'%0[dD]']
    injection_score = 0
    for value in header_dict.values():
        for pattern in injection_patterns:
            if re.search(pattern, value):
                injection_score += 1
                break
    features.append(injection_score / max(len(header_dict), 1))

    return features


def get_feature_names() -> List[str]:
    """
    Return names of all features of interpretability.
    """
    names = []

    # Expected headers
    for header in EXPECTED_HEADERS.keys():
        names.append(f"has_{header.lower().replace('-', '_')}")
    names.append("weighted_header_completeness")

    # User-agent features
    names.extend([
        "ua_length",
        "ua_suspicion_score",
        "ua_legitimate_score",
        "ua_entropy",
        "ua_char_diversity"
    ])

    # Statistics
    names.extend([
        "header_count",
        "avg_value_length",
        "max_value_length",
        "min_value_length",
        "std_value_length"
    ])

    # Structural features
    names.extent([
        "header_order_deviation",
        "case_consistency"
    ])

    # Anomaly features
    names.extend([
        "x_header_count",
        "duplicate_header_score",
        "suspicious_mime_type",
        "injection_attempt_score"
    ])

    return names