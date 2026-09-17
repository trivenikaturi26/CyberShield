"""
core/email_parser.py
CyberShield: Explainable Phishing URL & Email Security Analyzer

Email Decomposition & Normalization Module
Analyzes email text purely in memory without contacting mail servers,
DNS, mailboxes, or external APIs.

Extracted Components:
    - Sender raw string, display name, normalized email, sender domain
    - Subject and body text
    - Extracted URLs (supporting standard schemes, www, and defanged syntax)
    - Suspicious attachment filename references (.exe, .scr, .bat, etc.)
    - Lexical statistics (word count, uppercase ratio, exclamation count)
"""

import re
import email.utils
from typing import Any


# High-risk script/executable extensions commonly abused in phishing lure texts
SUSPICIOUS_EXTENSIONS = (
    "exe", "scr", "bat", "cmd", "js", "vbs", "ps1", "vbe", "wsf", "hta", "jar"
)

# Regex pattern for attachment filenames mentioned in text
ATTACHMENT_PATTERN = re.compile(
    r"\b[\w\-.]+\.(?:" + "|".join(SUSPICIOUS_EXTENSIONS) + r")\b",
    re.IGNORECASE,
)

# Regex pattern for URLs (standard http/https/ftp, defanged hxxp/hxxps, and bare www domains)
URL_PATTERN = re.compile(
    r"(?i)\b(?:(?:https?|hxxps?|ftp)://|www\.)[^\s<>\"'{}|\\^`\[\]]+",
    re.IGNORECASE,
)


def _clean_extracted_url(raw_url: str) -> str:
    """Strips trailing sentence punctuation that may adhere to a URL in raw text."""
    # Remove trailing periods, commas, closing brackets/parentheses, quotes
    cleaned = re.sub(r"[.,;:!?'\"\)>]+$", "", raw_url)
    return cleaned


def extract_urls_from_text(text: str) -> list[str]:
    """
    Statically discovers and normalizes URL strings contained within a text block.
    Does NOT visit or resolve any discovered URLs.
    """
    if not text or not isinstance(text, str):
        return []

    # Also detect bracket-defanged patterns like example[.]com/login
    defanged_normalized = text.replace("[.]", ".").replace("(.)", ".").replace("[/]", "/")
    
    matches = URL_PATTERN.findall(defanged_normalized)
    cleaned_urls = []
    seen = set()

    for m in matches:
        cleaned = _clean_extracted_url(m)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            cleaned_urls.append(cleaned)

    return cleaned_urls


def extract_attachment_references(text: str) -> list[str]:
    """
    Detects mentions of suspicious attachment filenames in the text.
    Does NOT execute, parse, or download any files.
    """
    if not text or not isinstance(text, str):
        return []

    matches = ATTACHMENT_PATTERN.findall(text)
    unique_matches = []
    seen = set()

    for m in matches:
        lower_m = m.lower()
        if lower_m not in seen:
            seen.add(lower_m)
            unique_matches.append(m)

    return unique_matches


def parse_sender_info(sender_raw: str) -> dict[str, str]:
    """
    Parses a sender field into display name, normalized email, and domain.
    Handles 'Name <email@domain.com>', 'email@domain.com', and edge formats.
    """
    if not sender_raw or not isinstance(sender_raw, str):
        return {
            "raw": "",
            "display_name": "",
            "email": "",
            "domain": "",
            "is_malformed": True,
        }

    cleaned = sender_raw.strip()
    name, addr = email.utils.parseaddr(cleaned)

    # Fallback if parseaddr fails but an '@' exists
    if not addr and "@" in cleaned:
        addr = cleaned.strip("<> \t\r\n")

    domain = ""
    is_malformed = False

    if addr and "@" in addr:
        parts = addr.split("@")
        if len(parts) == 2 and parts[1].strip():
            domain = parts[1].strip().lower()
        else:
            is_malformed = True
    else:
        is_malformed = True

    return {
        "raw": cleaned,
        "display_name": name.strip(),
        "email": addr.strip().lower(),
        "domain": domain,
        "is_malformed": is_malformed,
    }


def parse_email(sender: str, subject: str, body: str) -> dict[str, Any]:
    """
    Decomposes an email's sender, subject, and body into structured components.
    
    Strictly static and in-memory. Zero network traffic.
    
    Returns:
        dict: A structured dictionary containing:
            is_valid: bool
            error_message: str
            sender: str (raw sender string)
            sender_display_name: str
            sender_email: str
            sender_domain: str
            is_sender_malformed: bool
            subject: str
            body: str
            extracted_urls: list of URL strings found in body and subject
            url_count: int
            detected_attachments: list of referenced attachment filenames
            basic_stats: dict of lexical text metrics
    """
    sender_str = str(sender or "").strip()
    subject_str = str(subject or "").strip()
    body_str = str(body or "").strip()

    # Empty email validation
    if not sender_str and not subject_str and not body_str:
        return {
            "is_valid": False,
            "error_message": "Email input is completely empty. Please provide sender, subject, or body.",
            "sender": "",
            "sender_display_name": "",
            "sender_email": "",
            "sender_domain": "",
            "is_sender_malformed": True,
            "subject": "",
            "body": "",
            "extracted_urls": [],
            "url_count": 0,
            "detected_attachments": [],
            "basic_stats": {
                "word_count": 0,
                "char_count": 0,
                "uppercase_ratio": 0.0,
                "exclamation_count": 0,
            },
        }

    # Parse sender
    sender_info = parse_sender_info(sender_str)

    # Combine text for URL and attachment scanning
    full_text = f"{subject_str}\n{body_str}"

    # Extract URLs from subject and body
    extracted_urls = extract_urls_from_text(full_text)

    # Extract attachment references from subject and body
    detected_attachments = extract_attachment_references(full_text)

    # Compute text metrics
    words = body_str.split()
    word_count = len(words)
    char_count = len(body_str)
    
    alpha_chars = [c for c in full_text if c.isalpha()]
    upper_chars = [c for c in alpha_chars if c.isupper()]
    uppercase_ratio = (len(upper_chars) / len(alpha_chars)) if alpha_chars else 0.0
    exclamation_count = full_text.count("!")

    return {
        "is_valid": True,
        "error_message": "",
        "sender": sender_str,
        "sender_display_name": sender_info["display_name"],
        "sender_email": sender_info["email"],
        "sender_domain": sender_info["domain"],
        "is_sender_malformed": sender_info["is_malformed"],
        "subject": subject_str,
        "body": body_str,
        "extracted_urls": extracted_urls,
        "url_count": len(extracted_urls),
        "detected_attachments": detected_attachments,
        "basic_stats": {
            "word_count": word_count,
            "char_count": char_count,
            "uppercase_ratio": round(uppercase_ratio, 3),
            "exclamation_count": exclamation_count,
        },
    }
