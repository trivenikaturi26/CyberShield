"""
test_risk.py
CyberShield Phase 3: Automated Verification Test Suite for Risk Assessment

Verifies that core/risk.py adheres to:
1. Exact continuous threshold categories:
   - 0-20   : Low Concern
   - 21-59  : Review Recommended
   - 60-100 : Higher Concern
2. Accurate score clamping (0 to 100).
3. Non-triggered rules contribute 0 points.
4. Empty findings produce score 0 with clean fallback.
5. Exact point tracking and explanation aggregation.
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from core.risk import calculate_risk_score, get_risk_category, RULE_WEIGHTS


def create_mock_findings(triggered_rules_dict: dict) -> list[dict]:
    """
    Helper that constructs mock rule findings for specified rules and their triggered status.
    triggered_rules_dict format: { "Rule Name": True/False }
    """
    findings = []
    for rule_name, is_triggered in triggered_rules_dict.items():
        findings.append({
            "rule_name": rule_name,
            "triggered": is_triggered,
            "explanation": f"Test explanation for {rule_name}",
            "evidence": f"Test evidence for {rule_name}",
        })
    return findings


def run_risk_tests() -> int:
    failed_tests = 0
    total_tests = 0

    print("=" * 80)
    print("CYBERSHIELD - PHASE 3: RISK ASSESSMENT AUTOMATED VERIFICATION")
    print("=" * 80)

    # --------------------------------------------------------------------------
    # Test Part 1: Verify get_risk_category() at exact boundary & sample scores
    # --------------------------------------------------------------------------
    boundary_cases = [
        (0, "Low Concern"),
        (10, "Low Concern"),
        (20, "Low Concern"),             # Upper boundary of Low Concern
        (21, "Review Recommended"),      # Lower boundary of Review Recommended
        (40, "Review Recommended"),
        (59, "Review Recommended"),      # Upper boundary of Review Recommended
        (60, "Higher Concern"),          # Lower boundary of Higher Concern
        (90, "Higher Concern"),
        (100, "Higher Concern"),         # Maximum score
    ]

    print("\n--- PART 1: Category Boundary Verification ---")
    for score, expected_category in boundary_cases:
        total_tests += 1
        actual_category, _ = get_risk_category(score)
        passed = (actual_category == expected_category)
        status = "[PASS]" if passed else "[FAIL]"
        if not passed:
            failed_tests += 1
        print(f"  {status} Score: {score:3d} | Expected: '{expected_category:<18}' | Actual: '{actual_category}'")

    # --------------------------------------------------------------------------
    # Test Part 2: Verify calculate_risk_score() with specific rule combinations
    # --------------------------------------------------------------------------
    print("\n--- PART 2: Scoring Engine & Rule Accumulation Verification ---")

    # Case A: Empty findings produces score 0
    total_tests += 1
    result_empty = calculate_risk_score([])
    pass_a = (result_empty["total_score"] == 0 and result_empty["category"] == "Low Concern")
    if not pass_a:
        failed_tests += 1
    print(f"  {'[PASS]' if pass_a else '[FAIL]'} Empty findings -> Score: {result_empty['total_score']} (Category: {result_empty['category']})")

    # Case B: All rules evaluated, but NONE triggered -> Score: 0 (Low Concern)
    total_tests += 1
    all_false = {name: False for name in RULE_WEIGHTS}
    result_b = calculate_risk_score(create_mock_findings(all_false))
    pass_b = (result_b["total_score"] == 0 and len(result_b["triggered_rules"]) == 0 and result_b["category"] == "Low Concern")
    if not pass_b:
        failed_tests += 1
    print(f"  {'[PASS]' if pass_b else '[FAIL]'} All rules non-triggered -> Score: {result_b['total_score']} (Triggered list: {len(result_b['triggered_rules'])})")

    # Case C: Only HTTPS (10 pts) triggered -> Score: 10 (Low Concern)
    total_tests += 1
    findings_c = create_mock_findings({"HTTPS Usage Check": True, "URL Length Check": False})
    result_c = calculate_risk_score(findings_c)
    pass_c = (result_c["total_score"] == 10 and result_c["category"] == "Low Concern")
    if not pass_c:
        failed_tests += 1
    print(f"  {'[PASS]' if pass_c else '[FAIL]'} HTTPS only (+10 pts) -> Score: {result_c['total_score']} (Category: {result_c['category']})")

    # Case D: HTTPS (+10) + Length (+10) triggered -> Score: 20 (Boundary of Low Concern)
    total_tests += 1
    findings_d = create_mock_findings({"HTTPS Usage Check": True, "URL Length Check": True})
    result_d = calculate_risk_score(findings_d)
    pass_d = (result_d["total_score"] == 20 and result_d["category"] == "Low Concern")
    if not pass_d:
        failed_tests += 1
    print(f"  {'[PASS]' if pass_d else '[FAIL]'} HTTPS + Length (+20 pts) -> Score: {result_d['total_score']} (Category: {result_d['category']})")

    # Case E: IP Hostname (+30 pts) triggered -> Score: 30 (Review Recommended)
    total_tests += 1
    findings_e = create_mock_findings({"IP Address Hostname Check": True})
    result_e = calculate_risk_score(findings_e)
    pass_e = (result_e["total_score"] == 30 and result_e["category"] == "Review Recommended")
    if not pass_e:
        failed_tests += 1
    print(f"  {'[PASS]' if pass_e else '[FAIL]'} IP Hostname only (+30 pts) -> Score: {result_e['total_score']} (Category: {result_e['category']})")

    # Case F: IP Hostname (+30) + @ Symbol (+30) triggered -> Score: 60 (Boundary of Higher Concern)
    total_tests += 1
    findings_f = create_mock_findings({
        "IP Address Hostname Check": True,
        "@ Symbol User-Info Check": True,
    })
    result_f = calculate_risk_score(findings_f)
    pass_f = (result_f["total_score"] == 60 and result_f["category"] == "Higher Concern")
    if not pass_f:
        failed_tests += 1
    print(f"  {'[PASS]' if pass_f else '[FAIL]'} IP + @ Symbol (+60 pts) -> Score: {result_f['total_score']} (Category: {result_f['category']})")

    # Case G: All 6 rules triggered -> Score: 100 (Higher Concern)
    total_tests += 1
    all_true = {name: True for name in RULE_WEIGHTS}
    result_g = calculate_risk_score(create_mock_findings(all_true))
    pass_g = (
        result_g["total_score"] == 100
        and len(result_g["triggered_rules"]) == 6
        and result_g["category"] == "Higher Concern"
    )
    if not pass_g:
        failed_tests += 1
    print(f"  {'[PASS]' if pass_g else '[FAIL]'} All 6 rules triggered (+100 pts) -> Score: {result_g['total_score']} (Triggered: {len(result_g['triggered_rules'])})")

    # Case H: Score clamping (Score cannot exceed 100)
    total_tests += 1
    extra_findings = create_mock_findings(all_true)
    # Add a mock finding that would push score past 100 if unclamped
    extra_findings.append({
        "rule_name": "IP Address Hostname Check",
        "triggered": True,
        "explanation": "Duplicate rule trigger",
        "evidence": "Extra trigger",
    })
    result_h = calculate_risk_score(extra_findings)
    pass_h = (result_h["total_score"] == 100)
    if not pass_h:
        failed_tests += 1
    print(f"  {'[PASS]' if pass_h else '[FAIL]'} Clamping check (Overflow attempt) -> Score strictly capped at: {result_h['total_score']}")

    # Case I: Disclaimer presence check
    total_tests += 1
    pass_i = "does not prove" in result_g["disclaimer"] and "not a probability" in result_g["disclaimer"]
    if not pass_i:
        failed_tests += 1
    print(f"  {'[PASS]' if pass_i else '[FAIL]'} Security disclaimer verified: '{result_g['disclaimer'][:60]}...'")

    # --------------------------------------------------------------------------
    # Final Summary Report
    # --------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("TEST SUITE SUMMARY")
    print("=" * 80)
    print(f"  Total Checks Executed : {total_tests}")
    print(f"  Passed Checks         : {total_tests - failed_tests}")
    print(f"  Failed Checks         : {failed_tests}")

    if failed_tests == 0:
        print("\nOVERALL RESULT: ALL PHASE 3 RISK ASSESSMENT TESTS PASSED (100% SUCCESS)")
        print("=" * 80)
        return 0
    else:
        print(f"\nOVERALL RESULT: {failed_tests} TEST(S) FAILED")
        print("=" * 80)
        return 1


if __name__ == "__main__":
    sys.exit(run_risk_tests())
