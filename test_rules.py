"""
test_rules.py
CyberShield Phase 2: Automated Verification for Individual Heuristic Rules

Tests each of the 6 security heuristic rules independently against targeted URLs
to ensure accurate detection, clear evidence gathering, and zero false crashes.
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from core.parser import parse_url
from core.rules import (
    check_https_usage,
    check_ip_hostname,
    check_url_length,
    check_at_symbol,
    check_excessive_subdomains,
    check_suspicious_patterns,
    run_all_rules,
)


def run_rule_tests() -> int:
    """
    Verifies that each heuristic function detects its target indicator accurately.
    """
    tests = [
        # (Rule Function, Test URL, Expected Triggered (bool), Rule Name Label)
        (
            check_https_usage,
            "http://example.com/login",
            True,
            "HTTPS Rule - Unencrypted HTTP Trigger",
        ),
        (
            check_https_usage,
            "https://example.com/login",
            False,
            "HTTPS Rule - Secure HTTPS Normal",
        ),
        (
            check_ip_hostname,
            "http://192.168.1.1/admin",
            True,
            "IP Rule - IPv4 Address Trigger",
        ),
        (
            check_ip_hostname,
            "http://[::1]/admin",
            True,
            "IP Rule - IPv6 Address Trigger",
        ),
        (
            check_ip_hostname,
            "https://www.google.com",
            False,
            "IP Rule - Domain Host Normal",
        ),
        (
            check_url_length,
            "https://example.com/very/long/url/path/that/exceeds/the/default/threshold/of/seventy/five/characters/total",
            True,
            "Length Rule - Exceeds 75 chars Trigger",
        ),
        (
            check_url_length,
            "https://example.com/short",
            False,
            "Length Rule - Short URL Normal",
        ),
        (
            check_at_symbol,
            "http://paypal.com@evil-site.com/verify",
            True,
            "@ Symbol Rule - Credential Spoof Trigger",
        ),
        (
            check_at_symbol,
            "https://paypal.com/signin",
            False,
            "@ Symbol Rule - Normal Clean URL",
        ),
        (
            check_excessive_subdomains,
            "https://a.b.c.d.evil-domain.com/login",
            True,
            "Subdomain Rule - 4 Subdomains Trigger (>3)",
        ),
        (
            check_excessive_subdomains,
            "https://blog.example.com",
            False,
            "Subdomain Rule - 1 Subdomain Normal",
        ),
        (
            check_suspicious_patterns,
            "https://paypal-update-account-security-alert.com/login",
            True,
            "Pattern Rule - 4 Hyphens in Domain Trigger",
        ),
        (
            check_suspicious_patterns,
            "https://example.com//open-redirect//test",
            True,
            "Pattern Rule - Double Slash in Path Trigger",
        ),
        (
            check_suspicious_patterns,
            "https://www.google.com/search?q=test",
            False,
            "Pattern Rule - Normal Path and Domain",
        ),
    ]

    total_tests = len(tests)
    passed = 0
    failed = 0

    print("=" * 80)
    print("CYBERSHIELD - PHASE 2: INDIVIDUAL HEURISTIC RULES VERIFICATION")
    print("=" * 80)

    for idx, (rule_func, url, expected_triggered, description) in enumerate(tests, start=1):
        parsed = parse_url(url)
        rule_result = rule_func(parsed)
        actual_triggered = rule_result["triggered"]

        is_success = (actual_triggered == expected_triggered)
        if is_success:
            passed += 1
            tag = "[PASS]"
        else:
            failed += 1
            tag = "[FAIL]"

        print(f"\nTest {idx:02d}/{total_tests:02d}: {tag} - {description}")
        print(f"  URL Tested : '{url}'")
        print(f"  Triggered  : {actual_triggered} (Expected: {expected_triggered})")
        print(f"  Severity   : {rule_result['severity']}")
        print(f"  Evidence   : {rule_result['evidence']}")
        print(f"  Explanation: {rule_result['explanation']}")

    # Verification of run_all_rules helper
    print("\n" + "-" * 80)
    print("VERIFYING MASTER RUNNER: run_all_rules()")
    sample_phish = "http://paypal.com@verify-account-update.192.168.1.1/login//path"
    sample_parsed = parse_url(sample_phish)
    all_results = run_all_rules(sample_parsed)
    print(f"Sample Input: '{sample_phish}'")
    print(f"Total Rules Evaluated: {len(all_results)}")
    for res in all_results:
        status = "TRIGGERED" if res["triggered"] else "OK"
        print(f"  [{status:9s}] {res['rule_name']:<38} | {res['evidence']}")

    # Final summary
    print("\n" + "=" * 80)
    print("TEST SUITE SUMMARY")
    print("=" * 80)
    print(f"  Total Rule Checks : {total_tests}")
    print(f"  Passed Checks     : {passed}")
    print(f"  Failed Checks     : {failed}")

    if failed == 0:
        print("\nOVERALL RESULT: ALL PHASE 2 RULES PASSED (100% SUCCESS)")
        print("=" * 80)
        return 0
    else:
        print(f"\nOVERALL RESULT: {failed} RULE CHECK(S) FAILED")
        print("=" * 80)
        return 1


if __name__ == "__main__":
    sys.exit(run_rule_tests())
