"""
core/parser.py
CyberShield: Explainable Phishing URL Security Analyzer

Phase 1: URL Parsing and Validation Module
This module validates and decomposes a URL string into its standard components
without making any network connections or visiting the URL.
"""

from urllib.parse import urlsplit
import ipaddress


def is_ip_address(host: str) -> bool:
    """
    Checks if a given string is a valid IPv4 or IPv6 address.
    """
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def validate_url_input(raw_url: str) -> tuple[bool, str]:
    """
    Validates whether the raw input provided by the user is non-empty
    and has a reasonable, evaluatable string structure.

    Args:
        raw_url: The raw input string entered by the user.

    Returns:
        tuple (is_valid: bool, error_message: str)
    """
    # 1. Check if input is None or not a string
    if raw_url is None or not isinstance(raw_url, str):
        return False, "Input must be a valid text string."

    # 2. Check for empty string or whitespace-only string
    cleaned = raw_url.strip()
    if len(cleaned) == 0:
        return False, "Input cannot be empty."

    # 3. Check for unreasonable length (e.g., greater than 4096 characters)
    # RFC 7230 does not specify a limit, but practical systems cap URLs around 2000-4000 characters.
    if len(cleaned) > 4096:
        return False, "Input exceeds maximum supported URL length (4096 characters)."

    # 4. Check for spaces inside the URL (RFC standard URLs cannot contain unencoded spaces)
    if " " in cleaned:
        return False, "Invalid URL: URLs cannot contain spaces. Use '%20' for spaces."

    return True, ""


def parse_url(raw_url: str) -> dict:
    """
    Takes a raw URL string, validates it, and parses it into standard components:
    scheme, hostname, port, path, query, and fragment.

    Crucial: This function runs entirely locally and never triggers network traffic.

    Args:
        raw_url: The raw URL string to be parsed.

    Returns:
        dict: A structured dictionary containing parsed components and status.
    """
    # Step 1: Validate input first
    is_valid_input, error_msg = validate_url_input(raw_url)
    if not is_valid_input:
        return {
            "is_valid": False,
            "error_message": error_msg,
            "raw_url": raw_url,
            "normalized_url": "",
            "scheme": "",
            "netloc": "",
            "hostname": "",
            "port": None,
            "path": "",
            "query": "",
            "fragment": "",
        }

    cleaned_url = raw_url.strip()

    # Step 2: Handle defanged formats and missing schemes.
    # Security analysts frequently defang malicious URLs (e.g. hxxps://evil[.]com) to prevent accidental clicks.
    # We detect defanging, note it, and convert it to standard format for safe parsing.
    is_defanged = False
    working_url = cleaned_url

    if working_url.startswith("hxxps://"):
        working_url = "https://" + working_url[8:]
        is_defanged = True
    elif working_url.startswith("hxxp://"):
        working_url = "http://" + working_url[7:]
        is_defanged = True

    if "[.]" in working_url:
        working_url = working_url.replace("[.]", ".")
        is_defanged = True

    # In RFC 3986, if a URL starts with 'example.com' without 'http://' or '//',
    # urlsplit will treat 'example.com' as part of the path.
    # If no scheme is present, we prepend '//' so urlsplit identifies netloc/hostname.
    if "://" not in working_url and not working_url.startswith("//"):
        normalized_for_parsing = "//" + working_url
    else:
        normalized_for_parsing = working_url

    # Step 3: Parse using Python's standard library urlsplit
    try:
        split_result = urlsplit(normalized_for_parsing)
    except Exception as exc:
        return {
            "is_valid": False,
            "error_message": f"Malformed URL syntax: {str(exc)}",
            "raw_url": raw_url,
            "normalized_url": cleaned_url,
            "is_defanged": is_defanged,
            "scheme": "",
            "netloc": "",
            "hostname": "",
            "port": None,
            "path": "",
            "query": "",
            "fragment": "",
        }

    # Step 4: Extract and validate the hostname
    hostname = split_result.hostname or ""

    # Check if host exists
    if not hostname and not split_result.netloc:
        return {
            "is_valid": False,
            "error_message": "Invalid URL structure: Hostname/domain could not be determined.",
            "raw_url": raw_url,
            "normalized_url": cleaned_url,
            "is_defanged": is_defanged,
            "scheme": split_result.scheme,
            "netloc": "",
            "hostname": "",
            "port": None,
            "path": split_result.path,
            "query": split_result.query,
            "fragment": split_result.fragment,
        }

    # Verify that the hostname has a realistic structure:
    # A valid host must be a valid IP address (IPv4 or IPv6), contain at least one dot (domain name), or be 'localhost'
    if not is_ip_address(hostname) and "." not in hostname and hostname != "localhost":
        return {
            "is_valid": False,
            "error_message": "Invalid URL structure: Hostname must contain a valid domain (e.g., 'example.com') or IP address.",
            "raw_url": raw_url,
            "normalized_url": cleaned_url,
            "is_defanged": is_defanged,
            "scheme": split_result.scheme,
            "netloc": split_result.netloc,
            "hostname": hostname,
            "port": None,
            "path": split_result.path,
            "query": split_result.query,
            "fragment": split_result.fragment,
        }

    # Extract and validate port safely
    port = None
    try:
        port = split_result.port
    except ValueError:
        # urlsplit raises ValueError when port is non-numeric (e.g., 'example.com:abc')
        return {
            "is_valid": False,
            "error_message": "Invalid URL structure: Port must be a valid decimal integer between 0 and 65535.",
            "raw_url": raw_url,
            "normalized_url": cleaned_url,
            "is_defanged": is_defanged,
            "scheme": split_result.scheme,
            "netloc": split_result.netloc,
            "hostname": hostname,
            "port": None,
            "path": split_result.path,
            "query": split_result.query,
            "fragment": split_result.fragment,
        }

    # Step 5: Construct the parsed components dictionary
    return {
        "is_valid": True,
        "error_message": "",
        "raw_url": raw_url,
        "normalized_url": cleaned_url,
        "is_defanged": is_defanged,
        "scheme": split_result.scheme.lower() if split_result.scheme else "none",
        "netloc": split_result.netloc,
        "hostname": hostname.lower(),
        "port": port,
        "path": split_result.path if split_result.path else "/",
        "query": split_result.query,
        "fragment": split_result.fragment,
    }
