import re
import math
import ipaddress
from typing import Dict, List, Any
from collections import Counter
from datetime import datetime, timezone
from difflib import SequenceMatcher


SUSPICIOUS_HEADERS = {
    # Known malicious
    "X-Forwarded-Host": {"severity": "high", "reason": "Often used in host header injection"},
    "X-Original-URL": {"severity": "high", "reason": "Can bypass security controls"},
    "X-Rewrite_URL": {"severity": "high", "reason": "Can bypass security controls"},

    # Uncommon/suspicious
    "X-Custom-IP-Authorization": {"severity": "medium", "reason": "Non-standard auth header"},
    "X-Originating-IP": {"severity": "low", "reason": "May leak internal IP"},
    "X-Remote-IP": {"severity": "low", "reason": "May  leak internal IP"},
    "X-Client-IP": {"severity": "low", "reason": "May leak inernal IP"},

    # Testing/debug headers
    "X-Test": {"severity": "low", "reason": "Testing header in production"},
    "X-Debug": {"severity": "medium", "reason": "Debug header in production"},
    "X-Foo": {"severity": "low", "reason": "Placeholder header"},
}


def check_ip_anomalies(value: str) -> Dict[str, Any]:
    """
    Check for IP address anomalies.
    """
    anomalies = []

    # Extract potential IPs
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, value)

    for ip_str in ips:
        try:
            ip = ipaddress.ip_address(ip_str)

            # Check for private IPs in public context
            if ip.is_private:
                anomalies.append({
                    "type": "private_ip",
                    "value": ip_str,
                    "severity": "low"
                })

            # Check for loopback
            if ip.is_loopback:
                anomalies.append({
                    "type": "loopback_ip",
                    "value": ip_str,
                    "severity": "medium"
                })

            # Check for multicast
            if ip.is_multicast:
                anomalies.append({
                    "type": "multicast_ip",
                    "value": ip_str,
                    "severity": "low"
                })

        except ValueError:
            # Invalid IP
            anomalies.append({
                "type": "invalid_ip",
                "value": ip_str,
                "severity": "medium"
            })

    return {"ip_anomalies": anomalies} if anomalies else {}


def check_timing_anomalies(headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Check for timin-related anomalies.
    """
    anomalies = []

    # Check If-Modified-Since and If-Unmodified-Since
    date_headers = ["If-Modified-Since", "If-Unmodified-Since", "Date"]

    for header in date_headers:
        if header in headers:
            try:
                # Try to parse the date
                # FIXME update to proper http parsing [placeholder]
                if "9999" in headers[header] or "0000" in headers[header]:
                    anomalies.append({
                        "header": header,
                        "issue": "Suspicious date value",
                        "severity": "medium"
                    })
            except:
                pass

    return {"timing_anomalies": anomalies} if anomalies else {}


def check_encoding_chains(value: str) -> List[Dict[str, Any]]:
    """
    Detect multiple encoding layers.
    """
    issues = []

    # Check for double URL encoding
    if re.search(r'%25[0-9A-Fa-f]{2}', value):
        issues.append({
            "type": "double_url_encoding",
            "severity": "medium",
            "sample": value[:50]
        })

    # Check for mixed encoding
    if "%" in value and "+" in value:
        url_encoded = len(re.findall(r'%[0-9A-Fa-f]{2}', value))
        plus_encoded = value.count("+")
        if url_encoded > 0 and plus_encoded > 2:
            issues.append({
                "type": "mixed_encoding",
                "severity": "low",
                "detail": f"URL encoding: {url_encoded}, Plus encoding: {plus_encoded}"
            })

    return issues


def calculate_mutation_score(headers: Dict[str, str]) -> float:
    """
    Calculate a mutation score indicating howmuch headers deviate from standard patterns.
    """
    score = 0.0
    mutations = []

    # Check for case mutations in standard headers
    standard_headers = {
        "host": "Host",
        "user-agent": "User-Agent",
        "accept": "Accept",
        "content-type": "Content-Type",
        "authorization": "Authorization"
    }

    for key in headers.keys():
        lower_key = key.lower()
        if lower_key in standard_headers:
            if key != standard_headers[lower_key]:
                score += 0.2
                mutations.append(f"Non-standard casing: {key}")

    # Check for typos in common headers
    for header in headers.keys():
        for standard in standard_headers.values():
            similarity = SequenceMatcher(None, header.lower(), standard.lower()).ratio()
            if 0.7 < similarity < 1.0:
                score += 0.3
                mutations.append(f"Possible typo: {header} (similar to {standard})")

    # Check for unusual separators
    for key, value in headers.items():
        if "|" in value or ";;" in value or "::" in value:
            score += 0.1
            mutations.append(f"Unusual separator in {key}")

    return min(score, 1.0), mutations


def analyze_headers(header_dict: Dict[str, str]) -> Dict[str, Any]:
    """
    Comprehensive header analysis with multiple heuristic checks.
    """
    results = {
        "risk_score": 0.0,
        "missing_critical_headers": [],
        "missing_important_headers": [],
        "suspicious_headers": [],
        "encoding_issues": [],
        "structural_anomalies": [],
        "content_anomalies": [],
        "mutation_indicators": []
    }

    # Check for missing headers with severity levels
    critical_headers = ["Host", "User-Agent"]
    important_headers = ["Accept", "Accept-Encoding", "Accept-Language"]

    for header in critical_headers:
        if header not in header_dict:
            results["missing_critical_headers"].append(header)
            results["risk_score"] += 0.3

    for header in important_headers:
        if header not in header_dict:
            results["missing_important_headers"].append(header)
            results["risk_score"] += 0.1

    # Analyze each header
    for header, value in header_dict.items():
        # Check against suspicious patterns
        if header in SUSPICIOUS_HEADERS:
            results["suspicious_headers"].append({
                "header": header,
                "value": value[:100], # Truncate for safety
                "severity": SUSPICIOUS_HEADERS[header]["severity"],
                "reason": SUSPICIOUS_HEADERS[header]["reason"]
            })
            severity_scores = {"high": 0.4, "medium": 0.2, "low": 0.1}
            results["risk_score"] += severity_scores[SUSPICIOUS_HEADERS[header]["severity"]]

        # Check for encoding issues
        encoding_issues = check_encoding_chains(value)
        if encoding_issues:
            results["encoding_issues"].extend(encoding_issues)
            results["risk_score"] += severity_scores[SUSPICIOUS_HEADERS[header]["severity"]]

        # Check for IP anomalies
        ip_results = check_ip_anomalies(value)
        if ip_results:
            results["content_anomalies"].append(ip_results)
            results["risk_score"] += 0.05 * len(ip_results.get("ip_anomalies", []))

        # Check for header injection attempts
        if "\r" in value or "\n" in value:
            results["structural_anomalies"].append({
                "type": "header_injection",
                "header": header,
                "severity": "high"
            })
            results["risk_score"] += 0.5

        # Check for null bytes
        if "\x00" in value:
            results["structural_anomalies"].append({
                "type": "null_byte",
                "header": header,
                "severity": "high"
            })
            results["risk_score"] += 0.4

        # Check User-Agent specifically
        ua = header_dict.get("User-Agent", "")
        if ua:
            # Check for empty or very short UA
            if len(ua) < 10:
                results["content_anomalies"].append({
                    "type": "short_user_agent",
                    "length": len(ua),
                    "severity": "medium"
                })
                results["risk_score"] += 0.2

        # Check for script/automation tools
        automation_keywords = ["bot", "crawler", "spider", "scraper", "curl", "wget", "python", "java"]
        for keyword in automation_keywords:
            if keyword.lower() in ua.lower():
                results["content_anomalies"].append({
                    "type": "automation_tool",
                    "keyword": keyword,
                    "severity": "low" if keyword in ["bot", "crawler"] else "medium"
                })
                results["risk_score"] += 0.15
                break
    # Calculate mutation score
    mutation_score, mutations = calculate_mutation_score(header_dict)
    if mutation_score > 0:
        results["mutation_indicators"] = mutations
        results["mutation_score"] = mutation_score
        results["risk_score"] += mutation_score * 0.3

    # Check timing anomalies
    timing_results = check_timing_anomalies(header_dict)
    if timing_results:
        results["content_anomalies"].append(timing_results)
        results["risk_score"] += 0.1

    # Normalize risk score to 0 - 1 range
    results["risk_score"] = min(results["risk_score"], 1.0)

    # Add risk level classification
    if results["risk_score"] < 0.3:
        results["risk_level"] = "low"
    elif results["risk_score"] < 0.6:
        results["risk_level"] = "medium"
    else:
        results["risk_level"] = "high"

    return results