"""
test_email_risk.py
CyberShield: Explainable Phishing URL & Email Security Analyzer

Automated Verification Test Suite for core/email_risk.py
Verifies deterministic rule weight accumulation, strict 0-100 score clamping,
continuous risk tier boundaries, explainability fields, and disclaimer presence.
"""

import os
import sys

# Ensure the project root directory is in the Python module search path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from core.email_risk import (
    EMAIL_RULE_WEIGHTS,
    MAX_POSSIBLE_SCORE,
    HEURISTIC_EMAIL_DISCLAIMER,
    get_email_risk_category,
    calculate_email_risk_score,
)


def run_email_risk_suite() -> int:
    print("=" * 80)
    print("CYBERSHIELD: EMAIL RISK ASSESSMENT ENGINE VERIFICATION SUITE")
    print("=" * 80)

    total_checks = 0
    passed_checks = 0
    failed_checks = 0

    def record_check(description: str, condition: bool, details: str = ""):
        nonlocal total_checks, passed_checks, failed_checks
        total_checks += 1
        if condition:
            passed_checks += 1
            print(f"  [PASS] {description}")
        else:
            failed_checks += 1
            print(f"  [FAIL] {description} -> {details}")

    # --------------------------------------------------------------------------
    # 1. Weights Verification
    # --------------------------------------------------------------------------
    print("\n--- TEST 1: Rule Weights Mapping Verification ---")
    expected_weights = {
        "Credential Request": 20,
        "Account Threat": 15,
        "Suspicious Link": 15,
        "Suspicious Attachment": 15,
        "Urgency Language": 10,
        "Excessive Links": 10,
        "Financial Request": 10,
        "Sender Formatting": 10,
        "Generic Greeting": 5,
        "Excessive Punctuation": 5,
    }
    for r_name, exp_wt in expected_weights.items():
        actual_wt = EMAIL_RULE_WEIGHTS.get(r_name)
        record_check(f"Weight for '{r_name}' is +{exp_wt} pts", actual_wt == exp_wt, f"Got {actual_wt}")

    # --------------------------------------------------------------------------
    # 2. Category Boundary Verification
    # --------------------------------------------------------------------------
    print("\n--- TEST 2: Continuous Risk Category Boundaries ---")
    boundary_cases = [
        (0, "Low Concern"),
        (10, "Low Concern"),
        (20, "Low Concern"),
        (21, "Review Recommended"),
        (40, "Review Recommended"),
        (59, "Review Recommended"),
        (60, "Higher Concern"),
        (85, "Higher Concern"),
        (100, "Higher Concern"),
    ]
    for score, exp_cat in boundary_cases:
        cat, _ = get_email_risk_category(score)
        record_check(f"Score {score:>3} correctly maps to '{exp_cat}'", cat == exp_cat, f"Got '{cat}'")

    # --------------------------------------------------------------------------
    # 3. Empty & Safe Findings Handling
    # --------------------------------------------------------------------------
    print("\n--- TEST 3: Safe & Empty Findings Handling ---")
    empty_report = calculate_email_risk_score([])
    record_check("Empty list yields score 0", empty_report["total_score"] == 0)
    record_check("Category is Low Concern", empty_report["category"] == "Low Concern")
    record_check("Disclaimer included", HEURISTIC_EMAIL_DISCLAIMER in empty_report["disclaimer"])

    # Non-triggered findings
    non_triggered = [
        {"rule_name": "Urgency Language", "triggered": False, "explanation": "Clean", "evidence": "None"},
        {"rule_name": "Credential Request", "triggered": False, "explanation": "Clean", "evidence": "None"},
    ]
    non_trig_report = calculate_email_risk_score(non_triggered)
    record_check("Non-triggered rules yield score 0", non_trig_report["total_score"] == 0)
    record_check("Triggered rules list is empty", len(non_trig_report["triggered_rules"]) == 0)

    # --------------------------------------------------------------------------
    # 4. Point Accumulation & Tier Progression
    # --------------------------------------------------------------------------
    print("\n--- TEST 4: Score Accumulation Scenarios ---")
    # Low Concern: Generic Greeting only (+5)
    f_greeting = [{"rule_name": "Generic Greeting", "triggered": True, "explanation": "Generic", "evidence": "Dear user"}]
    rep1 = calculate_email_risk_score(f_greeting)
    record_check("Generic Greeting -> 5 pts (Low Concern)", rep1["total_score"] == 5 and rep1["category"] == "Low Concern")

    # Review Recommended: Urgency (+10) + Financial (+10) + Generic (+5) = 25 pts
    f_review = [
        {"rule_name": "Urgency Language", "triggered": True, "explanation": "Urgent", "evidence": "act now"},
        {"rule_name": "Financial Request", "triggered": True, "explanation": "Payment", "evidence": "wire transfer"},
        {"rule_name": "Generic Greeting", "triggered": True, "explanation": "Generic", "evidence": "Dear customer"},
    ]
    rep2 = calculate_email_risk_score(f_review)
    record_check("Urgency + Financial + Generic -> 25 pts (Review Recommended)", rep2["total_score"] == 25 and rep2["category"] == "Review Recommended")

    # Higher Concern: Credential Request (+20) + Account Threat (+15) + Suspicious Link (+15) + Urgency (+10) = 60 pts
    f_phish = [
        {"rule_name": "Credential Request", "triggered": True, "explanation": "Password", "evidence": "verify password"},
        {"rule_name": "Account Threat", "triggered": True, "explanation": "Locked", "evidence": "account suspended"},
        {"rule_name": "Suspicious Link", "triggered": True, "explanation": "Malicious link", "evidence": "raw IP URL"},
        {"rule_name": "Urgency Language", "triggered": True, "explanation": "Urgent", "evidence": "immediately"},
    ]
    rep3 = calculate_email_risk_score(f_phish)
    record_check("Credential + Threat + Link + Urgency -> 60 pts (Higher Concern)", rep3["total_score"] == 60 and rep3["category"] == "Higher Concern")

    # --------------------------------------------------------------------------
    # 5. Strict Score Clamping (100 Max)
    # --------------------------------------------------------------------------
    print("\n--- TEST 5: Score Clamping Verification ---")
    all_triggered = [
        {"rule_name": name, "triggered": True, "explanation": "Triggered", "evidence": "Evidence"}
        for name in expected_weights.keys()
    ]
    # Sum of all weights is 115 pts
    clamped_rep = calculate_email_risk_score(all_triggered)
    record_check("Unclamped sum would be 115 pts", sum(expected_weights.values()) == 115)
    record_check("Total score strictly clamped to 100", clamped_rep["total_score"] == 100)
    record_check("Max score reported as 100", clamped_rep["max_score"] == 100)
    record_check("All 10 rules captured in triggered list", len(clamped_rep["triggered_rules"]) == 10)

    # --------------------------------------------------------------------------
    # Final Summary
    # --------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("EMAIL RISK ENGINE TEST SUMMARY")
    print("=" * 80)
    print(f"  Total Checks Executed : {total_checks}")
    print(f"  Passed Checks         : {passed_checks}")
    print(f"  Failed Checks         : {failed_checks}")

    if failed_checks == 0:
        print("\nOVERALL RESULT: ALL EMAIL RISK ENGINE TESTS PASSED (100% SUCCESS)")
        print("=" * 80)
        return 0
    else:
        print(f"\nOVERALL RESULT: {failed_checks} CHECK(S) FAILED")
        print("=" * 80)
        return 1


if __name__ == "__main__":
    sys.exit(run_email_risk_suite())
