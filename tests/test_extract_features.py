from xweirdfor.extract_features import extract_features


def test_all_expected_headers_present():
    headers = {
        "Host": "a",
        "User-Agent": "b",
        "Accept": "c",
        "Accept-Encoding": "d",
        "Connection": "e",
        "Content-Type": "f",
        "X-Forwarded-For": "g",
        "Referer": "h"
    }
    features = extract_features(headers)
    assert features[0:8] == [1] * 8


def test_user_agent_length_and_bad_flag():
    headers = {
        "User-Agent": "curl/7.68.0"
    }
    features = extract_features(headers)
    ua_len = len("curl/7.68.0")

    assert features[8] == ua_len
    assert features[9] == 1


def test_header_count_and_avg_value_length():
    headers = {
        "Foo": "abc",
        "Bar": "defgh"
    }
    features = extract_features(headers)

    assert features[10] == 2
    assert features[11] == 4.0