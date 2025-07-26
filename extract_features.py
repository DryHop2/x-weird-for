EXPECTED_HEADERS = [
    "Host", "User-Agent", "Accept", "Accept-Encoding",
    "Connection", "Content-Type", "X-Forwarded-For", "Referer"
]

KNOWN_BAD_UA_PATTERNS = [
    "curl", "python", "wget", "bot", "scrapy", "requests"
]

def extract_features(header_dict):
    features = []

    for header in EXPECTED_HEADERS:
        features.append(1 if header in header_dict else 0)

    ua = header_dict.get("User-Agent", "")
    features.append(len(ua))
    features.append(1 if any(bad in ua.lower() for bad in KNOWN_BAD_UA_PATTERNS) else 0)

    features.append(len(header_dict))

    if header_dict:
        avg_val_len = sum(len(v) for v in header_dict.values()) / len(header_dict)
    else:
        avg_val_len = 0
    features.append(avg_val_len)

    return features