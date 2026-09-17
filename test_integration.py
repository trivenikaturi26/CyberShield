"""
test_integration.py
CyberShield Phase 4A: End-to-End Pipeline Integration Test

This script verifies the full, uninterrupted flow of CyberShield:
RAW URL -> core/parser.py -> core/rules.py -> core/risk.py -> EXPLAINABLE RESULT

Strictly static:
- No network requests
- No DNS lookups
- No URL visits
- No external APIs
"""

import os
import sys

# Ensure the root directory of the project is in the Python search path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from core.parser import parse_url
from core.rules import run_all_rules
from core.risk import calculate_risk_score


def analyze_url_pipeline(raw_url: str) -> dict:
    """
    Executes the complete CyberShield pipeline on a raw URL string.

    Returns a combined dictionary containing:
      - parser output
      - rule evaluation results
      - risk assessment report
    """
    # Step 1: Parse and validate structure
    parsed = parse_url(raw_url)

    # If the URL is structurally invalid, stop and return the parsing error
    if not parsed.get("is_valid", False):
        return {
            "status": "INVALID_URL",
            "raw_url": raw_url,
            "error_message": parsed.get("error_message", "Invalid URL structure"),
            "parsed": parsed,
            "rules": [],
            "risk": None,
        }

    # Step 2: Run all Phase 2 heuristic rules
    rule_findings = run_all_rules(parsed)

    # Step 3: Run Phase 3 risk assessment
    risk_assessment = calculate_risk_score(rule_findings)

    return {
        "status": "SUCCESS",
        "raw_url": raw_url,
        "error_message": "",
        "parsed": parsed,
        "rules": rule_findings,
        "risk": risk_assessment,
    }


def run_integration_suite() -> int:
    """
    Runs the integration test suite across all required test categories.
    """
    test_scenarios = [
        {
            "id": 1,
            "category": "Normal HTTPS Domain",
            "url": "https://www.google.com/search?q=cybersecurity",
            "expected_status": "SUCCESS",
            "expected_score": 0,
            "expected_category": "Low Concern",
        },
        {
            "id": 2,
            "category": "Plain HTTP URL",
            "url": "http://example.com/about-us",
            "expected_status": "SUCCESS",
            "expected_score": 10,  # HTTPS check triggers (+10)
            "expected_category": "Low Concern",
        },
        {
            "id": 3,
            "category": "Raw IP Address",
            "url": "https://192.168.1.1/admin/dashboard",
            "expected_status": "SUCCESS",
            "expected_score": 30,  # IP check triggers (+30)
            "expected_category": "Review Recommended",
        },
        {
            "id": 4,
            "category": "URL Containing @ Symbol",
            "url": "https://paypal.com@evil-attacker-site.com/verify",
            "expected_status": "SUCCESS",
            "expected_score": 30,  # @ symbol check triggers (+30)
            "expected_category": "Review Recommended",
        },
        {
            "id": 5,
            "category": "Long URL (>75 chars)",
            "url": "https://example.com/very/long/path/parameters/that/exceed/seventy/five/characters/total/length",
            "expected_status": "SUCCESS",
            "expected_score": 10,  # Length check triggers (+10)
            "expected_category": "Low Concern",
        },
        {
            "id": 6,
            "category": "Excessive Subdomains (4 levels)",
            "url": "https://login.verify.account.portal.evil-domain.com/signin",
            "expected_status": "SUCCESS",
            "expected_score": 10,  # Subdomain check triggers (+10)
            "expected_category": "Low Concern",
        },
        {
            "id": 7,
            "category": "Suspicious URL Pattern (Combosquatting Hyphens)",
            "url": "https://paypal-update-account-security-alert.com/login",
            "expected_status": "SUCCESS",
            "expected_score": 10,  # 4 hyphens trigger (+10)
            "expected_category": "Low Concern",
        },
        {
            "id": 8,
            "category": "Multiple Suspicious Indicators (Compounding Flags)",
            # HTTP (+10) + IP (+30) + @ symbol (+30) + Length > 75 (+10) + Double slash in path (+10) = 90 pts
            "url": "http://paypal.com@185.220.101.5/secure//login-verify-account-update.php?session=983274982374982374982374982374982374",
            "expected_status": "SUCCESS",
            "expected_score": 90,
            "expected_category": "Higher Concern",
        },
        {
            "id": 9,
            "category": "Invalid URL (Illegal Port Format)",
            "url": "https://example.com:abc",
            "expected_status": "INVALID_URL",
            "expected_score": None,
            "expected_category": None,
        },
    ]

    total_tests = len(test_scenarios)
    passed_tests = 0
    failed_tests = 0

    print("=" * 85)
    print("CYBERSHIELD - PHASE 4A: END-TO-END INTEGRATION TEST SUITE")
    print("=" * 85)

    for case in test_scenarios:
        t_id = case["id"]
        cat_name = case["category"]
        raw_url = case["url"]

        print(f"\n[Scenario {t_id:02d}/{total_tests:02d}] {cat_name}")
        print(f"  Input URL: '{raw_url}'")

        # Run the complete pipeline
        output = analyze_url_pipeline(raw_url)
        actual_status = output["status"]

        # Validate Scenario Expectation
        if case["expected_status"] == "INVALID_URL":
            test_passed = (actual_status == "INVALID_URL")
            if test_passed:
                passed_tests += 1
                status_badge = "[PASS]"
            else:
                failed_tests += 1
                status_badge = "[FAIL]"

            print(f"  Result Badge    : {status_badge}")
            print(f"  Status          : {actual_status} (Expected: INVALID_URL)")
            print(f"  Handled Error   : {output['error_message']}")

        else:
            risk = output["risk"]
            actual_score = risk["total_score"]
            actual_category = risk["category"]

            score_matches = (actual_score == case["expected_score"])
            cat_matches = (actual_category == case["expected_category"])
            test_passed = (actual_status == "SUCCESS" and score_matches and cat_matches)

            if test_passed:
                passed_tests += 1
                status_badge = "[PASS]"
            else:
                failed_tests += 1
                status_badge = "[FAIL]"

            print(f"  Result Badge    : {status_badge}")
            print(f"  Parsed Hostname : {output['parsed']['hostname']}")
            print(f"  Score           : {actual_score} / {risk['max_score']} (Expected: {case['expected_score']})")
            print(f"  Risk Category   : {actual_category} (Expected: {case['expected_category']})")
            print(f"  Triggered Rules : {len(risk['triggered_rules'])} of 6")

            if risk["triggered_rules"]:
                print("  --- Triggered Indicators Breakdown ---")
                for tr in risk["triggered_rules"]:
                    print(f"    • {tr['rule_name']} (+{tr['points_contributed']} pts)")
                    print(f"      Evidence: {tr['evidence']}")
                    print(f"      Reason  : {tr['explanation']}")
            else:
                print("  --- No Suspicious Indicators Triggered ---")

            if not test_passed:
                print(f"  >>> MISMATCH! Expected Score {case['expected_score']}, got {actual_score}")

    # --------------------------------------------------------------------------
    # Final Integration Summary Report
    # --------------------------------------------------------------------------
    print("\n" + "=" * 85)
    print("INTEGRATION TEST SUMMARY")
    print("=" * 85)
    print(f"  Total Integration Tests : {total_tests}")
    print(f"  Passed                  : {passed_tests}")
    print(f"  Failed                  : {failed_tests}")

    if failed_tests == 0:
        print("\nOVERALL RESULT: ALL INTEGRATION TESTS PASSED (100% SUCCESS)")
        print("=" * 85)
        return 0
    else:
        print(f"\nOVERALL RESULT: {failed_tests} TEST(S) FAILED")
        print("=" * 85)
        return 1


if __name__ == "__main__":
    sys.exit(run_integration_suite())
