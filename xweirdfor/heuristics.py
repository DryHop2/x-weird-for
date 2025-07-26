from extract_features import EXPECTED_HEADERS, KNOWN_BAD_UA_PATTERNS


UNCOMMON_HEADERS = {
    "X-Amzn-Trace-Id", "X-Foo", "X-Test", "DNT", "X-Requested-With"
}


def analyze_headers(header_dict):
    results = {
        "missing_expected_headers": [],
        "suspicious_headers": []
    }

    for header in EXPECTED_HEADERS:
        if header not in header_dict:
            results["missing_expected_headers"].append(header)

    ua = header_dict.get("User-Agent", "")
    for bad in KNOWN_BAD_UA_PATTERNS:
        if bad in ua.lower():
            results["suspicious_headers"].append({
                "header": "User-Agent",
                "value": ua,
                "reason": f"User-Agent contains suspicious string: '{bad}'"
            })
            break

    for header in header_dict:
        if header in UNCOMMON_HEADERS:
            results["suspicious_headers"].append({
                "header": header,
                "value": header_dict[header],
                "reason": "Header is uncommon or nonstandard"
            })

    return results