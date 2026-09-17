"""
test_parser.py
CyberShield Phase 1: Automated Verification Test Suite

This script verifies that the core URL parser and validation module functions
accurately against RFC 3986 standards, rejects malformed/empty inputs,
and safely parses both benign and suspicious URL structures without network calls.
"""

import os
import sys

# Ensure the project root directory is in the Python module search path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from core.parser import parse_url


def run_verification_suite() -> int:
    """
    Executes all Phase 1 test cases, compares actual results against expected results,
    and returns 0 if all tests pass, or 1 if any test fails.
    """
    test_cases = [
        # ----------------------------------------------------------------------
        # Group 1: Standard Benign URLs (Expected: Valid)
        # ----------------------------------------------------------------------
        (
            "https://www.example.com/index.html",
            "Normal valid HTTPS URL",
            True,
        ),
        (
            "https://www.google.com/search?q=cybersecurity#results",
            "Standard HTTPS with path, query, and fragment",
            True,
        ),
        (
            "http://example.com:8080/dashboard",
            "HTTP with valid non-standard numeric port",
            True,
        ),
        (
            "github.com/torvalds/linux",
            "Missing scheme (schemeless URL)",
            True,
        ),
        
        # ----------------------------------------------------------------------
        # Group 2: IP Address Formats (IPv4 & IPv6) (Expected: Valid)
        # ----------------------------------------------------------------------
        (
            "http://192.168.1.1:80/login.php",
            "Raw IPv4 address URL with standard port",
            True,
        ),
        (
            "http://[::1]/login",
            "Valid IPv6 loopback URL with bracketed RFC format",
            True,
        ),

        # ----------------------------------------------------------------------
        # Group 3: Suspicious Phishing Syntaxes (Syntactically Valid URLs)
        # Note: Even though these URLs are deceptive, their syntax adheres to RFC 3986,
        # so the Phase 1 parser must successfully parse their components.
        # ----------------------------------------------------------------------
        (
            "http://paypal.com@attacker-site.com/verify-account",
            "URL using @ symbol credential spoofing",
            True,
        ),
        (
            "https://secure.banking.paypal.com.evil-domain.xyz/auth?user=victim",
            "Subdomain brand spoofing with high-risk TLD",
            True,
        ),
        (
            "hxxps://malicious-link.top/invoice.pdf",
            "Defanged URL input (hxxps:// -> https://)",
            True,
        ),

        # ----------------------------------------------------------------------
        # Group 4: Malformed and Invalid Inputs (Expected: Invalid)
        # ----------------------------------------------------------------------
        (
            "https://example.com:abc",
            "Invalid/non-numeric port (:abc is not a valid decimal port)",
            False,
        ),
        (
            "",
            "Empty string input",
            False,
        ),
        (
            "   ",
            "Whitespace-only input",
            False,
        ),
        (
            "https://invalid url with spaces.com",
            "URL containing raw unencoded spaces",
            False,
        ),
        (
            "not_a_valid_url",
            "Random string without domain structure or dot",
            False,
        ),
    ]

    total_tests = len(test_cases)
    passed_tests = 0
    failed_tests = 0

    print("=" * 80)
    print("CYBERSHIELD - PHASE 1: URL PARSER AUTOMATED VERIFICATION")
    print("=" * 80)

    for idx, (url, description, expected_valid) in enumerate(test_cases, start=1):
        actual_result = parse_url(url)
        actual_valid = actual_result.get("is_valid", False)
        
        # Determine PASS or FAIL
        test_passed = (actual_valid == expected_valid)
        
        if test_passed:
            passed_tests += 1
            status_tag = "[PASS]"
        else:
            failed_tests += 1
            status_tag = "[FAIL]"

        print(f"\nTest {idx:02d}/{total_tests:02d}: {status_tag} - {description}")
        print(f"  Input URL       : '{url}'")
        print(f"  Expected Valid  : {expected_valid}")
        print(f"  Actual Valid    : {actual_valid}")

        if not test_passed:
            print(f"  >>> MISMATCH! Reason/Error: {actual_result.get('error_message', 'No error message')}")
        elif not actual_valid:
            print(f"  Handled Error   : {actual_result.get('error_message')}")
        else:
            print(f"  Parsed Scheme   : {actual_result.get('scheme')}")
            print(f"  Parsed Hostname : {actual_result.get('hostname')}")
            print(f"  Parsed Port     : {actual_result.get('port')}")
            print(f"  Parsed Path     : {actual_result.get('path')}")

    # ----------------------------------------------------------------------
    # Final Summary Report
    # ----------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("TEST SUITE SUMMARY")
    print("=" * 80)
    print(f"  Total Tests Executed : {total_tests}")
    print(f"  Tests Passed         : {passed_tests}")
    print(f"  Tests Failed         : {failed_tests}")
    
    if failed_tests == 0:
        print("\nOVERALL RESULT: ALL TESTS PASSED (100% SUCCESS)")
        print("=" * 80)
        return 0
    else:
        print(f"\nOVERALL RESULT: {failed_tests} TEST(S) FAILED")
        print("=" * 80)
        return 1


if __name__ == "__main__":
    exit_code = run_verification_suite()
    sys.exit(exit_code)
