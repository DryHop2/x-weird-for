from xweirdfor.heuristics import analyze_headers


def test_missing_expected_headers():
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*"
    }
    result = analyze_headers(headers)
    expected_missing = {
        "Host", "Accept-Encoding", "Connection", "Content-Type", "X-Forwarded-For", "Referer"
    }

    assert set(result["missing_expected_headers"]) == expected_missing


def test_known_bad_user_agent():
    headers = {
        "User-Agent": "python-requests/2.31"
    }
    result = analyze_headers(headers)
    suspicious = result["suspicious_headers"]

    assert any("User-Agent" == h["header"] and "python" in h["value"].lower() for h in suspicious)


def test_uncommon_header_flagged():
    headers = {
        "User-Agent": "Mozilla/5.0",
        "X-Test": "1"
    }
    result = analyze_headers(headers)

    assert any(h["header"] == "X-Test" for h in result["suspicious_headers"])