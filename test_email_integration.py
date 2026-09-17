"""
test_email_integration.py
CyberShield: Explainable Phishing URL & Email Security Analyzer

End-to-End Email Phishing Analysis Integration Test Suite
Verifies the complete, uninterrupted analysis pipeline:
  RAW EMAIL -> core/email_parser.py -> core/email_rules.py ->
  (Extracted URLs -> core/parser.py -> core/rules.py -> core/risk.py) ->
  core/email_risk.py -> EXPLAINABLE COMBINED RESULT

Required Test Scenarios:
  1. Normal benign email
  2. Urgent account warning
  3. Credential request
  4. Financial request
  5. Email containing a suspicious-looking URL
  6. Email containing an attachment filename reference
  7. Multiple compounding indicators together
  8. Empty / invalid input

Strictly static: Zero network calls, zero URL visits, zero file executions.
"""

import os
import sys
from typing import Any

# Ensure the project root directory is in the Python module search path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from core.email_parser import parse_email
from core.email_rules import run_all_email_rules
from core.email_risk import calculate_email_risk_score
from core.parser import parse_url
from core.rules import run_all_rules
from core.risk import calculate_risk_score


def analyze_email_pipeline(sender: str, subject: str, body: str) -> dict[str, Any]:
    """
    Executes the full CyberShield email analysis pipeline.
    Connects to the verified URL analyzer for any extracted URLs.
    """
    # Step 1: Parse and decompose the email text
    parsed_email = parse_email(sender, subject, body)

    if not parsed_email.get("is_valid", False):
        return {
            "status": "INVALID_INPUT",
            "error_message": parsed_email.get("error_message", "Invalid email structure"),
            "parsed_email": parsed_email,
            "analyzed_urls": [],
            "rule_findings": [],
            "risk_report": None,
        }

    # Step 2: Feed any extracted URLs into the existing URL analysis pipeline
    analyzed_urls = []
    for raw_url in parsed_email.get("extracted_urls", []):
        parsed_u = parse_url(raw_url)
        if parsed_u.get("is_valid", False):
            u_rules = run_all_rules(parsed_u)
            u_assessment = calculate_risk_score(u_rules)
            analyzed_urls.append({
                "raw_url": raw_url,
                "parsed": parsed_u,
                "total_score": u_assessment["total_score"],
                "max_score": u_assessment["max_score"],
                "category": u_assessment["category"],
                "triggered_rules": u_assessment["triggered_rules"],
            })
        else:
            analyzed_urls.append({
                "raw_url": raw_url,
                "parsed": parsed_u,
                "total_score": 0,
                "max_score": 100,
                "category": "Invalid URL",
                "triggered_rules": [],
            })

    # Step 3: Run all 10 email heuristic rules (incorporating URL results)
    rule_findings = run_all_email_rules(parsed_email, analyzed_urls)

    # Step 4: Calculate final weighted email risk assessment
    risk_report = calculate_email_risk_score(rule_findings, analyzed_urls)

    return {
        "status": "SUCCESS",
        "error_message": "",
        "parsed_email": parsed_email,
        "analyzed_urls": analyzed_urls,
        "rule_findings": rule_findings,
        "risk_report": risk_report,
    }


def run_email_integration_suite() -> int:
    print("=" * 85)
    print("CYBERSHIELD: END-TO-END EMAIL PIPELINE INTEGRATION TEST SUITE")
    print("=" * 85)

    test_scenarios = [
        # Scenario 1: Normal benign email
        {
            "id": 1,
            "name": "Normal Benign Email",
            "sender": "Alice Smith <alice@example.com>",
            "subject": "Project Meeting Agenda for Thursday",
            "body": "Hi team, please find our meeting notes at https://company.org/notes. Let me know if you have questions.",
            "expected_category": "Low Concern",
            "expected_rules_triggered": [],
            "max_expected_score": 20,
        },
        # Scenario 2: Urgent account warning
        {
            "id": 2,
            "name": "Urgent Account Warning",
            "sender": "Security Alerts <alerts@my-service.com>",
            "subject": "URGENT: Security alert regarding your account",
            "body": "We detected unauthorized access to your account. Your account will be suspended within 24 hours.",
            "expected_category": "Review Recommended",
            "expected_rules_triggered": ["Urgency Language", "Account Threat"],
            "min_expected_score": 25,
        },
        # Scenario 3: Credential request
        {
            "id": 3,
            "name": "Credential Request",
            "sender": "IT Admin <admin@company.org>",
            "subject": "Action Required: System Verification",
            "body": "Dear employee, we are migrating servers immediately. Please confirm your username and password or security code.",
            "expected_category": "Review Recommended",
            "expected_rules_triggered": ["Credential Request", "Urgency Language"],
            "min_expected_score": 25,
        },
        # Scenario 4: Financial request
        {
            "id": 4,
            "name": "Financial / Payment Request",
            "sender": "Billing Department <billing@vendor-invoices.com>",
            "subject": "Notice: Overdue Invoice Payment Required Immediately",
            "body": "Dear customer, invoice payment failed. Immediate bank transfer required within 24 hours to avoid disruption.",
            "expected_category": "Review Recommended",
            "expected_rules_triggered": ["Financial Request", "Urgency Language", "Generic Greeting"],
            "min_expected_score": 25,
        },
        # Scenario 5: Email containing a suspicious-looking URL (Raw IP + HTTP)
        {
            "id": 5,
            "name": "Email Containing Suspicious-Looking URL",
            "sender": "Notice <notice@service-portal.com>",
            "subject": "Portal Link Updated",
            "body": "Access your portal here: http://192.168.1.1/admin/login",
            "expected_category": "Low Concern",  # Only suspicious link triggers (15 pts) -> 15 <= 20
            "expected_rules_triggered": ["Suspicious Link"],
            "url_test_check": lambda urls: len(urls) > 0 and urls[0]["total_score"] > 0,
        },
        # Scenario 6: Email containing an attachment filename reference
        {
            "id": 6,
            "name": "Email Referencing Executable Attachment",
            "sender": "Shipment Desk <track@package-update.com>",
            "subject": "Your package delivery label",
            "body": "Your parcel could not be delivered. Please download and review the attached delivery_slip.exe to reschedule.",
            "expected_category": "Low Concern",  # Only attachment triggers (15 pts)
            "expected_rules_triggered": ["Suspicious Attachment"],
            "min_expected_score": 15,
        },
        # Scenario 7: Multiple compounding indicators together (High Severity)
        {
            "id": 7,
            "name": "Compounding Multiple Phishing Indicators",
            "sender": "PayPal Support <security@service-alerts-update.xyz>",
            "subject": "URGENT: Your PayPal account will be suspended immediately!!!",
            "body": (
                "Dear customer, your account will be suspended within 24 hours due to suspicious activity. "
                "You must verify now! Please submit your password and credit card details here: "
                "http://192.168.1.1/login.php. Also run patch_fix.bat to secure your connection."
            ),
            "expected_category": "Higher Concern",
            "expected_rules_triggered": [
                "Urgency Language",
                "Account Threat",
                "Credential Request",
                "Suspicious Link",
                "Financial Request",
                "Suspicious Attachment",
                "Generic Greeting",
                "Sender Formatting",
                "Excessive Punctuation",
            ],
            "min_expected_score": 60,
        },
        # Scenario 8: Empty / invalid input
        {
            "id": 8,
            "name": "Empty / Invalid Input",
            "sender": "",
            "subject": "",
            "body": "",
            "expected_status": "INVALID_INPUT",
        },
    ]

    total_scenarios = len(test_scenarios)
    passed_scenarios = 0
    failed_scenarios = 0

    for scenario in test_scenarios:
        s_id = scenario["id"]
        s_name = scenario["name"]
        print(f"\n[Scenario {s_id:02d}/{total_scenarios:02d}] {s_name}")

        output = analyze_email_pipeline(
            scenario["sender"], scenario["subject"], scenario["body"]
        )

        scenario_passed = True
        failure_reasons = []

        # Check for expected invalid status
        if scenario.get("expected_status") == "INVALID_INPUT":
            if output["status"] == "INVALID_INPUT":
                print("  Status          : INVALID_INPUT (Handled gracefully)")
                print(f"  Handled Message : {output['error_message']}")
            else:
                scenario_passed = False
                failure_reasons.append(f"Expected INVALID_INPUT, got {output['status']}")
        else:
            if output["status"] != "SUCCESS":
                scenario_passed = False
                failure_reasons.append(f"Pipeline failed: {output['error_message']}")
            else:
                risk = output["risk_report"]
                score = risk["total_score"]
                cat = risk["category"]
                triggered_names = [r["rule_name"] for r in risk["triggered_rules"]]

                print(f"  Email Risk Score : {score} / {risk['max_score']}")
                print(f"  Risk Category    : {cat}")
                print(f"  Triggered Rules  : {len(triggered_names)} of 10 ({', '.join(triggered_names) if triggered_names else 'None'})")
                print(f"  Extracted URLs   : {len(output['analyzed_urls'])}")

                # Check expected category if specified
                if "expected_category" in scenario:
                    if cat != scenario["expected_category"]:
                        scenario_passed = False
                        failure_reasons.append(f"Expected category '{scenario['expected_category']}', got '{cat}'")

                # Check minimum expected score if specified
                if "min_expected_score" in scenario:
                    if score < scenario["min_expected_score"]:
                        scenario_passed = False
                        failure_reasons.append(f"Expected score >= {scenario['min_expected_score']}, got {score}")

                # Check maximum expected score if specified
                if "max_expected_score" in scenario:
                    if score > scenario["max_expected_score"]:
                        scenario_passed = False
                        failure_reasons.append(f"Expected score <= {scenario['max_expected_score']}, got {score}")

                # Check triggered rules
                for req_rule in scenario.get("expected_rules_triggered", []):
                    if req_rule not in triggered_names:
                        scenario_passed = False
                        failure_reasons.append(f"Required rule '{req_rule}' was not triggered")

                # Check URL integration hook if specified
                if "url_test_check" in scenario:
                    if not scenario["url_test_check"](output["analyzed_urls"]):
                        scenario_passed = False
                        failure_reasons.append("URL integration check failed")

        if scenario_passed:
            passed_scenarios += 1
            print("  Result Badge     : [PASS]")
        else:
            failed_scenarios += 1
            print(f"  Result Badge     : [FAIL] -> {'; '.join(failure_reasons)}")

    print("\n" + "=" * 85)
    print("EMAIL INTEGRATION TEST SUMMARY")
    print("=" * 85)
    print(f"  Total Scenarios : {total_scenarios}")
    print(f"  Passed          : {passed_scenarios}")
    print(f"  Failed          : {failed_scenarios}")

    if failed_scenarios == 0:
        print("\nOVERALL RESULT: ALL EMAIL INTEGRATION TESTS PASSED (100% SUCCESS)")
        print("=" * 85)
        return 0
    else:
        print(f"\nOVERALL RESULT: {failed_scenarios} SCENARIO(S) FAILED")
        print("=" * 85)
        return 1


if __name__ == "__main__":
    sys.exit(run_email_integration_suite())
