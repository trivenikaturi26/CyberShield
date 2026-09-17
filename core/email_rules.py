"""
core/email_rules.py
CyberShield: Explainable Phishing URL & Email Security Analyzer

Email Security Heuristic Rules Module
Implements 10 independent, transparent, rule-based security indicators
that analyze the parsed email dictionary from core/email_parser.py.

Safety & Isolation:
    - Pure in-memory analysis of text strings.
    - No network connections, no DNS, no external APIs.
    - Does not visit or download anything.
    - Returns structured findings with rule name, triggered status,
      points, evidence, and security explanation.
"""

import re
from typing import Any, Optional


# ------------------------------------------------------------------------------
# Heuristic Pattern Definitions
# ------------------------------------------------------------------------------

# Rule 1: Urgency phrases
URGENCY_PATTERNS = [
    r"\burgent\b",
    r"\bimmediately\b",
    r"\bact now\b",
    r"\bwithin 24 hours\b",
    r"\bwithin 48 hours\b",
    r"\bverify now\b",
    r"\bfinal warning\b",
    r"\baction required\b",
    r"\btime-sensitive\b",
    r"\bexpires in\b",
    r"\blimited time\b",
    r"\bprompt attention\b",
]

# Rule 2: Account threats & alerts
THREAT_PATTERNS = [
    r"\baccount (?:will be|has been|is) suspended\b",
    r"\baccount locked\b",
    r"\baccess (?:will be|has been) disabled\b",
    r"\baccount (?:will be|has been) terminated\b",
    r"\bsecurity alert\b",
    r"\bunauthorized (?:access|activity|sign-in)\b",
    r"\bsuspicious (?:activity|login)\b",
    r"\brestricted account\b",
    r"\bnotice of termination\b",
    r"\bprevent account closure\b",
]

# Rule 3: Credential requests
CREDENTIAL_PATTERNS = [
    r"\b(?:enter|verify|confirm|update|submit)\b[^\n.]{0,30}\b(?:password|passcode)\b",
    r"\bpassword\b",
    r"\blogin credentials\b",
    r"\busername and password\b",
    r"\botp\b",
    r"\bone-time password\b",
    r"\bsecurity pin\b",
    r"\bsecurity code\b",
    r"\bverification code\b",
    r"\bconfirm your credentials\b",
    r"\bverify your identity\b",
]

# Rule 6: Financial/payment requests
FINANCIAL_PATTERNS = [
    r"\bpayment required\b",
    r"\bbank transfer\b",
    r"\bcard verification\b",
    r"\binvoice payment\b",
    r"\bpayment failed\b",
    r"\brefund claim\b",
    r"\bwire transfer\b",
    r"\bupdate payment method\b",
    r"\bbilling update\b",
    r"\boverdue invoice\b",
    r"\bcredit card (?:number|details|expiry)\b",
    r"\bcrypto(?:currency)?\b",
    r"\bbitcoin\b",
]

# Rule 8: Generic Greetings
GENERIC_GREETINGS = [
    r"\bdear customer\b",
    r"\bdear user\b",
    r"\bdear account holder\b",
    r"\bdear client\b",
    r"\bdear member\b",
    r"\bvalued customer\b",
    r"\battention:? account holder\b",
    r"\bdear sir/madam\b",
    r"\bdear cardholder\b",
    r"\bdear email user\b",
]

# Common targeted brand names to inspect for display name spoofing
KNOWN_BRANDS = [
    ("paypal", "paypal.com"),
    ("microsoft", "microsoft.com"),
    ("google", "google.com"),
    ("apple", "apple.com"),
    ("amazon", "amazon.com"),
    ("netflix", "netflix.com"),
    ("chase", "chase.com"),
    ("bank of america", "bankofamerica.com"),
    ("wells fargo", "wellsfargo.com"),
    ("facebook", "facebook.com"),
    ("meta", "meta.com"),
    ("dhl", "dhl.com"),
    ("fedex", "fedex.com"),
]


# ------------------------------------------------------------------------------
# Individual Rule Implementations
# ------------------------------------------------------------------------------

def check_urgency_language(parsed_email: dict) -> dict[str, Any]:
    """Rule 1: Detects high-pressure urgency keywords in subject or body."""
    rule_name = "Urgency Language"
    subject = parsed_email.get("subject", "")
    body = parsed_email.get("body", "")
    full_text = f"{subject}\n{body}".lower()

    matches = []
    for pattern in URGENCY_PATTERNS:
        found = re.findall(pattern, full_text)
        if found:
            matches.extend(found)

    if matches:
        unique_matches = sorted(set(matches))
        return {
            "rule_name": rule_name,
            "triggered": True,
            "severity": "MEDIUM",
            "evidence": f"Found {len(unique_matches)} urgency phrase(s): '{', '.join(unique_matches)}'",
            "explanation": "The email employs high-urgency language designed to induce panic and hasty action.",
        }

    return {
        "rule_name": rule_name,
        "triggered": False,
        "severity": "LOW",
        "evidence": "No high-pressure urgency keywords detected.",
        "explanation": "Standard communication pacing without artificial urgency triggers.",
    }


def check_account_threat(parsed_email: dict) -> dict[str, Any]:
    """Rule 2: Detects phrases warning of account suspension, lockout, or closure."""
    rule_name = "Account Threat"
    subject = parsed_email.get("subject", "")
    body = parsed_email.get("body", "")
    full_text = f"{subject}\n{body}".lower()

    matches = []
    for pattern in THREAT_PATTERNS:
        found = re.findall(pattern, full_text)
        if found:
            matches.extend(found)

    if matches:
        unique_matches = sorted(set(matches))
        return {
            "rule_name": rule_name,
            "triggered": True,
            "severity": "HIGH",
            "evidence": f"Detected account threat phrase(s): '{', '.join(unique_matches)}'",
            "explanation": "The email uses account disruption threats or simulated security alerts to compel compliance.",
        }

    return {
        "rule_name": rule_name,
        "triggered": False,
        "severity": "LOW",
        "evidence": "No account suspension or security alert threats detected.",
        "explanation": "Standard informational content without coercion or lockout threats.",
    }


def check_credential_request(parsed_email: dict) -> dict[str, Any]:
    """Rule 3: Detects direct requests for passwords, usernames, OTPs, or PINs."""
    rule_name = "Credential Request"
    subject = parsed_email.get("subject", "")
    body = parsed_email.get("body", "")
    full_text = f"{subject}\n{body}".lower()

    matches = []
    for pattern in CREDENTIAL_PATTERNS:
        found = re.findall(pattern, full_text)
        if found:
            matches.extend(found)

    if matches:
        unique_matches = sorted(set(matches))
        return {
            "rule_name": rule_name,
            "triggered": True,
            "severity": "HIGH",
            "evidence": f"Detected credential solicitation: '{', '.join(unique_matches)}'",
            "explanation": "The email explicitly solicits passwords, authentication codes, or login credentials.",
        }

    return {
        "rule_name": rule_name,
        "triggered": False,
        "severity": "LOW",
        "evidence": "No explicit credential or password requests detected.",
        "explanation": "No sensitive authentication tokens or passwords requested in the text.",
    }


def check_suspicious_link_presence(
    parsed_email: dict, analyzed_urls: Optional[list[dict]] = None
) -> dict[str, Any]:
    """
    Rule 4: Evaluates embedded links using the existing CyberShield URL analyzer.
    Does NOT automatically flag clean URLs as malicious.
    """
    rule_name = "Suspicious Link"
    extracted_urls = parsed_email.get("extracted_urls", [])

    if not extracted_urls:
        return {
            "rule_name": rule_name,
            "triggered": False,
            "severity": "LOW",
            "evidence": "No embedded URLs detected in the email text.",
            "explanation": "The email contains no clickable links or web addresses.",
        }

    # If URL analysis results from existing URL engine are supplied:
    if analyzed_urls:
        suspicious_urls = [
            u for u in analyzed_urls if u.get("total_score", 0) > 0 or u.get("category") != "Low Concern"
        ]
        if suspicious_urls:
            evidences = [
                f"{u['raw_url']} (Score: {u['total_score']}/100, Tier: {u['category']})"
                for u in suspicious_urls[:3]
            ]
            return {
                "rule_name": rule_name,
                "triggered": True,
                "severity": "HIGH",
                "evidence": f"Found {len(suspicious_urls)} suspicious URL(s): {'; '.join(evidences)}",
                "explanation": "One or more embedded links triggered structural anomalies or high-risk URL indicators in the CyberShield URL analyzer.",
            }
        else:
            return {
                "rule_name": rule_name,
                "triggered": False,
                "severity": "LOW",
                "evidence": f"Found {len(extracted_urls)} URL(s), all evaluated as Low Concern by the URL analyzer.",
                "explanation": "Embedded URLs conform to standard legitimate structures without detected heuristic flags.",
            }

    # Fallback if evaluated standalone: check for suspicious scheme or auth indicators in raw strings
    suspicious_raw = [
        u for u in extracted_urls if "http://" in u.lower() or "@" in u or "//" in u.split("://")[-1]
    ]
    if suspicious_raw:
        return {
            "rule_name": rule_name,
            "triggered": True,
            "severity": "HIGH",
            "evidence": f"Detected suspicious URL patterns: '{', '.join(suspicious_raw[:2])}'",
            "explanation": "Embedded URLs exhibit unencrypted HTTP protocols, @ symbol user-info, or path anomalies.",
        }

    return {
        "rule_name": rule_name,
        "triggered": False,
        "severity": "LOW",
        "evidence": f"Found {len(extracted_urls)} standard URL string(s).",
        "explanation": "URL strings present appear standard; evaluated via URL analyzer.",
    }


def check_excessive_links(parsed_email: dict) -> dict[str, Any]:
    """Rule 5: Detects an unusually large number of embedded links (>= 3)."""
    rule_name = "Excessive Links"
    url_count = parsed_email.get("url_count", 0)

    if url_count >= 3:
        return {
            "rule_name": rule_name,
            "triggered": True,
            "severity": "MEDIUM",
            "evidence": f"Detected {url_count} distinct embedded URLs (Threshold: >= 3).",
            "explanation": "A high number of embedded links is often used in phishing lures to disperse traps or confuse recipients.",
        }

    return {
        "rule_name": rule_name,
        "triggered": False,
        "severity": "LOW",
        "evidence": f"URL count: {url_count} (Below threshold of 3).",
        "explanation": "The quantity of embedded links is within normal bounds.",
    }


def check_financial_request(parsed_email: dict) -> dict[str, Any]:
    """Rule 6: Detects financial demands, wire transfers, invoices, or billing urgency."""
    rule_name = "Financial Request"
    subject = parsed_email.get("subject", "")
    body = parsed_email.get("body", "")
    full_text = f"{subject}\n{body}".lower()

    matches = []
    for pattern in FINANCIAL_PATTERNS:
        found = re.findall(pattern, full_text)
        if found:
            matches.extend(found)

    if matches:
        unique_matches = sorted(set(matches))
        return {
            "rule_name": rule_name,
            "triggered": True,
            "severity": "MEDIUM",
            "evidence": f"Detected financial keyword(s): '{', '.join(unique_matches)}'",
            "explanation": "The email requests urgent financial transactions, payment details, or invoice settlements.",
        }

    return {
        "rule_name": rule_name,
        "triggered": False,
        "severity": "LOW",
        "evidence": "No financial transaction or billing demand indicators detected.",
        "explanation": "Text contains no explicit payment, card, or invoice solicitations.",
    }


def check_suspicious_attachments(parsed_email: dict) -> dict[str, Any]:
    """Rule 7: Detects explicit references to high-risk executable or script filenames."""
    rule_name = "Suspicious Attachment"
    attachments = parsed_email.get("detected_attachments", [])

    if attachments:
        return {
            "rule_name": rule_name,
            "triggered": True,
            "severity": "HIGH",
            "evidence": f"Detected high-risk attachment reference(s): '{', '.join(attachments)}'",
            "explanation": "The email references executable or script files (.exe, .scr, .bat, etc.) commonly leveraged for malware delivery.",
        }

    return {
        "rule_name": rule_name,
        "triggered": False,
        "severity": "LOW",
        "evidence": "No executable or script attachment extensions referenced.",
        "explanation": "No high-risk file types (.exe, .scr, .js, .bat) detected in the text.",
    }


def check_generic_greeting(parsed_email: dict) -> dict[str, Any]:
    """Rule 8: Detects depersonalized generic greetings (low-weight indicator)."""
    rule_name = "Generic Greeting"
    body = parsed_email.get("body", "").lower()

    matches = []
    for pattern in GENERIC_GREETINGS:
        found = re.findall(pattern, body)
        if found:
            matches.extend(found)

    if matches:
        unique_matches = sorted(set(matches))
        return {
            "rule_name": rule_name,
            "triggered": True,
            "severity": "LOW",
            "evidence": f"Found generic greeting: '{', '.join(unique_matches)}'",
            "explanation": "The email uses a generic, depersonalized greeting often seen in mass phishing campaigns.",
        }

    return {
        "rule_name": rule_name,
        "triggered": False,
        "severity": "LOW",
        "evidence": "No depersonalized generic greetings detected.",
        "explanation": "Greeting appears personalized or omitted.",
    }


def check_sender_formatting(parsed_email: dict) -> dict[str, Any]:
    """
    Rule 9: Inspects basic sender syntax and checks for display name spoofing
    (e.g., Display says 'PayPal Support' but actual domain is 'scam-mail.xyz').
    """
    rule_name = "Sender Formatting"
    display_name = parsed_email.get("sender_display_name", "").lower()
    sender_domain = parsed_email.get("sender_domain", "").lower()
    is_malformed = parsed_email.get("is_sender_malformed", False)
    raw_sender = parsed_email.get("sender", "")

    # Malformed email address check
    if is_malformed and raw_sender:
        return {
            "rule_name": rule_name,
            "triggered": True,
            "severity": "MEDIUM",
            "evidence": f"Malformed sender address syntax: '{raw_sender}'",
            "explanation": "The sender string does not follow standard RFC email address formatting.",
        }

    # Brand display name mismatch check
    for brand, legit_domain in KNOWN_BRANDS:
        if brand in display_name:
            # Check if domain matches the legitimate brand domain
            if sender_domain and not (
                sender_domain == legit_domain or sender_domain.endswith("." + legit_domain)
            ):
                return {
                    "rule_name": rule_name,
                    "triggered": True,
                    "severity": "HIGH",
                    "evidence": f"Display name claims '{brand.title()}' but domain is '{sender_domain}' (Expected '{legit_domain}').",
                    "explanation": "Obvious display name spoofing detected: the sender claims a known brand while sending from an unrelated domain.",
                }

    # Check for raw IP address in domain
    if sender_domain and re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", sender_domain):
        return {
            "rule_name": rule_name,
            "triggered": True,
            "severity": "HIGH",
            "evidence": f"Sender domain is a numerical IP address: '{sender_domain}'",
            "explanation": "Legitimate mail organizations do not send email from raw IP hostnames.",
        }

    return {
        "rule_name": rule_name,
        "triggered": False,
        "severity": "LOW",
        "evidence": f"Sender domain '{sender_domain or 'None'}' matches standard syntax.",
        "explanation": "No obvious sender format irregularities or display name mismatches detected.",
    }


def check_excessive_punctuation(parsed_email: dict) -> dict[str, Any]:
    """Rule 10: Detects aggressive punctuation (!!!) or high uppercase ratio."""
    rule_name = "Excessive Punctuation"
    subject = parsed_email.get("subject", "")
    body = parsed_email.get("body", "")
    full_text = f"{subject}\n{body}"
    stats = parsed_email.get("basic_stats", {})

    exclamation_count = stats.get("exclamation_count", full_text.count("!"))
    uppercase_ratio = stats.get("uppercase_ratio", 0.0)

    # Trigger conditions: multiple consecutive exclamation marks or high exclamations with caps
    has_multiple_bangs = bool(re.search(r"!{2,}", full_text))
    is_shouting = (uppercase_ratio > 0.35 and len(full_text) > 30) or (
        has_multiple_bangs and exclamation_count >= 3
    )

    if is_shouting or has_multiple_bangs:
        evid_parts = []
        if has_multiple_bangs:
            evid_parts.append(f"Multiple consecutive exclamation marks detected ({exclamation_count} total '!')")
        if uppercase_ratio > 0.35:
            evid_parts.append(f"High uppercase ratio ({int(uppercase_ratio * 100)}%)")
        return {
            "rule_name": rule_name,
            "triggered": True,
            "severity": "LOW",
            "evidence": "; ".join(evid_parts),
            "explanation": "Aggressive punctuation or capitalization patterns are behavioral indicators of coercive pressure.",
        }

    return {
        "rule_name": rule_name,
        "triggered": False,
        "severity": "LOW",
        "evidence": f"Punctuation and capitalization within normal levels (Exclamations: {exclamation_count}).",
        "explanation": "Text follows standard typographical conventions.",
    }


# ------------------------------------------------------------------------------
# All Rules Runner
# ------------------------------------------------------------------------------

def run_all_email_rules(
    parsed_email: dict, analyzed_urls: Optional[list[dict]] = None
) -> list[dict[str, Any]]:
    """
    Executes all 10 email security heuristic rules sequentially.
    Returns a list of structured findings dictionaries.
    """
    return [
        check_urgency_language(parsed_email),
        check_account_threat(parsed_email),
        check_credential_request(parsed_email),
        check_suspicious_link_presence(parsed_email, analyzed_urls),
        check_excessive_links(parsed_email),
        check_financial_request(parsed_email),
        check_suspicious_attachments(parsed_email),
        check_generic_greeting(parsed_email),
        check_sender_formatting(parsed_email),
        check_excessive_punctuation(parsed_email),
    ]
