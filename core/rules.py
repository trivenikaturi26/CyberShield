"""
core/rules.py
CyberShield: Explainable Phishing URL Security Analyzer

Phase 2: Individual Security Heuristic Rules Module
This module implements independent, transparent heuristic detection functions
that analyze the parsed URL dictionary from core/parser.py.

Each function:
- Analyzes only the parsed URL components.
- Never makes network connections.
- Returns a structured dictionary with:
    rule_name: str
    triggered: bool
    severity: str ("LOW", "MEDIUM", "HIGH")
    explanation: str
    evidence: str
"""

import ipaddress


def check_https_usage(parsed_url: dict) -> dict:
    """
    Rule 1: Checks whether the URL utilizes encrypted HTTPS transport.
    
    Security context:
    While HTTPS does not guarantee a website is legitimate, plain HTTP means
    credentials and data are transmitted unencrypted, which is abnormal
    for legitimate modern authentication portals.
    """
    rule_name = "HTTPS Usage Check"
    scheme = parsed_url.get("scheme", "").lower()

    if scheme == "https":
        return {
            "rule_name": rule_name,
            "triggered": False,
            "severity": "LOW",
            "explanation": "The URL uses secure, encrypted HTTPS protocol.",
            "evidence": "Scheme: https",
        }
    elif scheme == "http":
        return {
            "rule_name": rule_name,
            "triggered": True,
            "severity": "LOW",
            "explanation": "The URL uses unencrypted HTTP protocol. Sensitive data entered here can be intercepted.",
            "evidence": "Scheme: http",
        }
    else:
        return {
            "rule_name": rule_name,
            "triggered": True,
            "severity": "LOW",
            "explanation": f"The URL lacks an explicit secure HTTPS protocol (Found: '{scheme}').",
            "evidence": f"Scheme: {scheme}",
        }


def check_ip_hostname(parsed_url: dict) -> dict:
    """
    Rule 2: Checks whether the hostname is a numerical IP address (IPv4 or IPv6)
    instead of a registered domain name.
    
    Security context:
    Legitimate public web services use registered domain names. Phishing kits
    frequently use raw IP addresses to bypass domain reputation filters and
    avoid domain registration identity records.
    """
    rule_name = "IP Address Hostname Check"
    hostname = parsed_url.get("hostname", "")

    # Test if hostname parses as a valid IPv4 or IPv6 address
    is_ip = False
    ip_version = None
    try:
        ip_obj = ipaddress.ip_address(hostname)
        is_ip = True
        ip_version = f"IPv{ip_obj.version}"
    except ValueError:
        is_ip = False

    if is_ip:
        return {
            "rule_name": rule_name,
            "triggered": True,
            "severity": "HIGH",
            "explanation": f"The URL uses a raw {ip_version} address instead of a registered domain name. This is a common indicator of temporary phishing kits or compromised infrastructure.",
            "evidence": f"Hostname: {hostname} ({ip_version})",
        }

    return {
        "rule_name": rule_name,
        "triggered": False,
        "severity": "HIGH",
        "explanation": "The URL uses a named domain rather than a raw IP address.",
        "evidence": f"Hostname: {hostname}",
    }


def check_url_length(parsed_url: dict, threshold: int = 75) -> dict:
    """
    Rule 3: Evaluates the total length of the URL.
    
    Security context:
    Phishing URLs frequently exceed 75 characters to hide deceptive subdomains,
    embed tracking tokens, or push the true domain name off-screen on mobile devices.
    """
    rule_name = "URL Length Check"
    raw_url = parsed_url.get("raw_url", "")
    url_length = len(raw_url)

    if url_length > threshold:
        return {
            "rule_name": rule_name,
            "triggered": True,
            "severity": "MEDIUM",
            "explanation": f"The URL length ({url_length} characters) exceeds the normal threshold ({threshold} characters). Attackers often use lengthy URLs to conceal deceptive domains or embed payload parameters.",
            "evidence": f"Length: {url_length} chars (Threshold: {threshold})",
        }

    return {
        "rule_name": rule_name,
        "triggered": False,
        "severity": "LOW",
        "explanation": f"The URL length ({url_length} characters) is within the normal expected range.",
        "evidence": f"Length: {url_length} chars",
    }


def check_at_symbol(parsed_url: dict) -> dict:
    """
    Rule 4: Detects the '@' symbol in the URL authority / netloc.
    
    Security context:
    In RFC 3986, characters before '@' represent user credentials (userinfo),
    while browsers navigate to the hostname *after* the '@'. Attackers exploit this
    to display a trusted brand name before '@' while routing the victim elsewhere.
    """
    rule_name = "@ Symbol User-Info Check"
    raw_url = parsed_url.get("raw_url", "")
    netloc = parsed_url.get("netloc", "")

    # Check if '@' appears in netloc or raw URL
    if "@" in netloc or "@" in raw_url:
        return {
            "rule_name": rule_name,
            "triggered": True,
            "severity": "HIGH",
            "explanation": "The '@' symbol was detected in the URL. Attackers use this technique to make users believe they are visiting a trusted domain when the browser actually connects to the server after the '@'.",
            "evidence": "Found '@' symbol in authority structure",
        }

    return {
        "rule_name": rule_name,
        "triggered": False,
        "severity": "HIGH",
        "explanation": "No '@' symbol trick detected in URL authority.",
        "evidence": "Clean authority syntax",
    }


def check_excessive_subdomains(parsed_url: dict, threshold: int = 3) -> dict:
    """
    Rule 5: Counts the number of subdomain layers in the hostname.
    
    Security context:
    Phishers chain multiple subdomains (e.g. login.paypal.com.verify.evil.com)
    to visually mimic genuine brand portals and confuse end-users.
    """
    rule_name = "Excessive Subdomain Check"
    hostname = parsed_url.get("hostname", "")

    # If the hostname is an IP address, subdomains are not applicable
    try:
        ipaddress.ip_address(hostname)
        return {
            "rule_name": rule_name,
            "triggered": False,
            "severity": "MEDIUM",
            "explanation": "Hostname is an IP address; subdomain analysis skipped.",
            "evidence": f"Hostname: {hostname}",
        }
    except ValueError:
        pass

    # Split the hostname by dots (e.g. 'a.b.c.example.com' -> ['a', 'b', 'c', 'example', 'com'])
    labels = [label for label in hostname.split(".") if label]
    
    # In a standard domain (example.com), there are 2 labels: domain + TLD.
    # Any labels beyond that are subdomains.
    # Subdomain count = total labels - 2
    subdomain_count = max(0, len(labels) - 2)

    if subdomain_count > threshold:
        return {
            "rule_name": rule_name,
            "triggered": True,
            "severity": "MEDIUM",
            "explanation": f"The hostname contains {subdomain_count} subdomain levels, which exceeds the threshold ({threshold}). Multiple subdomains are frequently chained to spoof brand names.",
            "evidence": f"Subdomain levels: {subdomain_count} ({'.'.join(labels[:-2])})",
        }

    return {
        "rule_name": rule_name,
        "triggered": False,
        "severity": "LOW",
        "explanation": f"The hostname has {subdomain_count} subdomain levels, which is within normal limits.",
        "evidence": f"Subdomain levels: {subdomain_count}",
    }


def check_suspicious_patterns(parsed_url: dict) -> dict:
    """
    Rule 6: Identifies anomalous syntactic patterns like:
    - Double slashes ('//') in the URL path (Open Redirect or path manipulation).
    - Excessive hyphens in the domain (combosquatting indicator, e.g. 3 or more hyphens).
    """
    rule_name = "Suspicious Character & Pattern Check"
    path = parsed_url.get("path", "")
    hostname = parsed_url.get("hostname", "")

    findings = []

    # Check 1: Double slashes in path (excluding the initial scheme separator '://')
    if "//" in path:
        findings.append("Double slash ('//') detected inside the URL path.")

    # Check 2: Excessive hyphens in the hostname (3 or more hyphens)
    hyphen_count = hostname.count("-")
    if hyphen_count >= 3:
        findings.append(f"Excessive hyphens in hostname ({hyphen_count} hyphens). Often indicates combosquatting lure domains.")

    if findings:
        return {
            "rule_name": rule_name,
            "triggered": True,
            "severity": "MEDIUM",
            "explanation": " ".join(findings),
            "evidence": f"Path: '{path}' | Hyphens in host: {hyphen_count}",
        }

    return {
        "rule_name": rule_name,
        "triggered": False,
        "severity": "LOW",
        "explanation": "No suspicious syntax patterns (double slashes in path or excessive domain hyphens) detected.",
        "evidence": "Standard path and domain character composition",
    }


def run_all_rules(parsed_url: dict) -> list[dict]:
    """
    Helper runner that executes all 6 individual rules sequentially
    and returns a list of the findings.
    
    Crucial: This function does NOT calculate a final score or declare
    the URL malicious, maintaining strict rule independence.
    """
    return [
        check_https_usage(parsed_url),
        check_ip_hostname(parsed_url),
        check_url_length(parsed_url),
        check_at_symbol(parsed_url),
        check_excessive_subdomains(parsed_url),
        check_suspicious_patterns(parsed_url),
    ]
