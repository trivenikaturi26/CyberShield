"""
test_email_rules.py
CyberShield: Explainable Phishing URL & Email Security Analyzer

Automated Verification Test Suite for core/email_rules.py
Tests all 10 transparent email heuristic rules individually in both
triggered and passing states, verifying evidence and explanation fields.
"""

import os
import sys

# Ensure the project root directory is in the Python module search path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from core.email_parser import parse_email
from core.email_rules import (
    check_urgency_language,
    check_account_threat,
    check_credential_request,
    check_suspicious_link_presence,
    check_excessive_links,
    check_financial_request,
    check_suspicious_attachments,
    check_generic_greeting,
    check_sender_formatting,
    check_excessive_punctuation,
    run_all_email_rules,
)


def run_email_rules_suite() -> int:
    print("=" * 80)
    print("CYBERSHIELD: EMAIL HEURISTIC RULES VERIFICATION TEST SUITE")
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
    # Rule 1: Urgency Language
    # --------------------------------------------------------------------------
    print("\n--- Rule 1: Urgency Language ---")
    p_urgent = parse_email("support@test.com", "Urgent: Action required immediately", "Please act now within 24 hours.")
    res = check_urgency_language(p_urgent)
    record_check("Triggered on urgent words", res["triggered"] is True)
    record_check("Urgency evidence present", "urgent" in res["evidence"].lower())

    p_calm = parse_email("newsletter@weekly.com", "Monthly Update", "Here are the articles published this month.")
    res = check_urgency_language(p_calm)
    record_check("Not triggered on standard pacing", res["triggered"] is False)

    # --------------------------------------------------------------------------
    # Rule 2: Account Threat
    # --------------------------------------------------------------------------
    print("\n--- Rule 2: Account Threat ---")
    p_threat = parse_email("alerts@service.com", "Security Alert", "Your account will be suspended due to unauthorized access.")
    res = check_account_threat(p_threat)
    record_check("Triggered on account suspension threat", res["triggered"] is True)
    record_check("High severity assigned", res["severity"] == "HIGH")

    p_safe = parse_email("info@service.com", "Welcome to your account", "Your account is active and ready to use.")
    res = check_account_threat(p_safe)
    record_check("Not triggered on benign account mention", res["triggered"] is False)

    # --------------------------------------------------------------------------
    # Rule 3: Credential Request
    # --------------------------------------------------------------------------
    print("\n--- Rule 3: Credential Request ---")
    p_cred = parse_email("admin@portal.com", "Verify Password", "Please confirm your password and security code immediately.")
    res = check_credential_request(p_cred)
    record_check("Triggered on password solicitation", res["triggered"] is True)
    record_check("Evidence captures credential request", "password" in res["evidence"].lower())

    p_nocred = parse_email("sales@shop.com", "Receipt #12345", "Thank you for purchasing our book.")
    res = check_credential_request(p_nocred)
    record_check("Not triggered when credentials not requested", res["triggered"] is False)

    # --------------------------------------------------------------------------
    # Rule 4: Suspicious Link Presence
    # --------------------------------------------------------------------------
    print("\n--- Rule 4: Suspicious Link Presence ---")
    # Case with suspicious URL from URL analyzer
    p_link = parse_email("help@pay.com", "Verify", "Visit http://192.168.1.1/login")
    mock_analyzed_suspicious = [{
        "raw_url": "http://192.168.1.1/login",
        "total_score": 40,
        "category": "Review Recommended",
    }]
    res = check_suspicious_link_presence(p_link, mock_analyzed_suspicious)
    record_check("Triggered when URL engine reports suspicious URL", res["triggered"] is True)
    record_check("Evidence mentions URL score", "Score: 40/100" in res["evidence"])

    # Case with clean URL from URL analyzer
    mock_analyzed_clean = [{
        "raw_url": "https://www.google.com",
        "total_score": 0,
        "category": "Low Concern",
    }]
    p_clean_link = parse_email("news@google.com", "Search", "Search at https://www.google.com")
    res = check_suspicious_link_presence(p_clean_link, mock_analyzed_clean)
    record_check("Not triggered when all URLs are Low Concern", res["triggered"] is False)

    # Case with no links at all
    p_no_link = parse_email("friend@chat.com", "Hello", "Just wanted to say hello.")
    res = check_suspicious_link_presence(p_no_link, [])
    record_check("Not triggered when no links present", res["triggered"] is False)

    # --------------------------------------------------------------------------
    # Rule 5: Excessive Links
    # --------------------------------------------------------------------------
    print("\n--- Rule 5: Excessive Links ---")
    p_many_links = parse_email(
        "promo@deals.com",
        "Multiple Offers",
        "Link 1: https://site1.com Link 2: https://site2.com Link 3: https://site3.com Link 4: https://site4.com"
    )
    res = check_excessive_links(p_many_links)
    record_check("Triggered on >= 3 links", res["triggered"] is True, f"Count: {p_many_links['url_count']}")

    p_few_links = parse_email("support@site.com", "Contact", "Visit our help center: https://site.com/help")
    res = check_excessive_links(p_few_links)
    record_check("Not triggered on single link", res["triggered"] is False)

    # --------------------------------------------------------------------------
    # Rule 6: Financial / Payment Request
    # --------------------------------------------------------------------------
    print("\n--- Rule 6: Financial / Payment Request ---")
    p_finance = parse_email("billing@invoice-dept.com", "Overdue Invoice", "Payment required immediately via bank transfer for invoice payment.")
    res = check_financial_request(p_finance)
    record_check("Triggered on payment demands", res["triggered"] is True)
    record_check("Financial evidence captured", "payment" in res["evidence"].lower())

    p_social = parse_email("meetup@club.com", "Next meeting", "Our next meetup will be on Saturday at the library.")
    res = check_financial_request(p_social)
    record_check("Not triggered on non-financial message", res["triggered"] is False)

    # --------------------------------------------------------------------------
    # Rule 7: Suspicious Attachment References
    # --------------------------------------------------------------------------
    print("\n--- Rule 7: Suspicious Attachment References ---")
    p_attach = parse_email("shipping@courier.com", "Delivery Tracking", "Open the attached shipment_label.exe to confirm your address.")
    res = check_suspicious_attachments(p_attach)
    record_check("Triggered on .exe attachment reference", res["triggered"] is True)
    record_check("Attachment filename identified", "shipment_label.exe" in res["evidence"].lower())

    p_no_attach = parse_email("hr@corp.com", "Policy", "Please see our employee handbook online.")
    res = check_suspicious_attachments(p_no_attach)
    record_check("Not triggered without executable references", res["triggered"] is False)

    # --------------------------------------------------------------------------
    # Rule 8: Generic Greeting
    # --------------------------------------------------------------------------
    print("\n--- Rule 8: Generic Greeting ---")
    p_generic = parse_email("bank@alert.com", "Notice", "Dear customer, your profile requires review.")
    res = check_generic_greeting(p_generic)
    record_check("Triggered on 'Dear customer'", res["triggered"] is True)
    record_check("Severity is LOW for generic greeting", res["severity"] == "LOW")

    p_named = parse_email("colleague@work.com", "Lunch", "Hi Sarah, are you available for lunch today?")
    res = check_generic_greeting(p_named)
    record_check("Not triggered on personal greeting", res["triggered"] is False)

    # --------------------------------------------------------------------------
    # Rule 9: Sender Domain Formatting
    # --------------------------------------------------------------------------
    print("\n--- Rule 9: Sender Domain Formatting ---")
    p_spoof = parse_email("PayPal Support <security@suspicious-domain.xyz>", "Security Alert", "Please check your account.")
    res = check_sender_formatting(p_spoof)
    record_check("Triggered on brand name vs domain mismatch", res["triggered"] is True)
    record_check("Evidence points out brand mismatch", "paypal" in res["evidence"].lower() and "suspicious-domain.xyz" in res["evidence"])

    p_legit_sender = parse_email("PayPal Support <service@paypal.com>", "Receipt", "You sent a payment of $10.")
    res = check_sender_formatting(p_legit_sender)
    record_check("Not triggered when brand matches legitimate domain", res["triggered"] is False)

    # --------------------------------------------------------------------------
    # Rule 10: Excessive Capitalization / Punctuation
    # --------------------------------------------------------------------------
    print("\n--- Rule 10: Excessive Capitalization / Punctuation ---")
    p_shout = parse_email("alert@system.com", "URGENT ACTION REQUIRED!!!", "CLICK NOW!!! VERIFY YOUR ACCOUNT!!!")
    res = check_excessive_punctuation(p_shout)
    record_check("Triggered on multiple !!! and all-caps", res["triggered"] is True)

    p_quiet = parse_email("prof@university.edu", "Assignment 3", "Please submit your assignment by Friday afternoon.")
    res = check_excessive_punctuation(p_quiet)
    record_check("Not triggered on standard punctuation", res["triggered"] is False)

    # --------------------------------------------------------------------------
    # Full Runner Check
    # --------------------------------------------------------------------------
    print("\n--- Full Runner Check (run_all_email_rules) ---")
    all_findings = run_all_email_rules(p_urgent)
    record_check("Runner returns exactly 10 rules", len(all_findings) == 10)
    record_check("All findings contain required schema keys", all(
        {"rule_name", "triggered", "severity", "evidence", "explanation"}.issubset(f.keys())
        for f in all_findings
    ))

    # --------------------------------------------------------------------------
    # Final Summary
    # --------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("EMAIL RULES TEST SUMMARY")
    print("=" * 80)
    print(f"  Total Checks Executed : {total_checks}")
    print(f"  Passed Checks         : {passed_checks}")
    print(f"  Failed Checks         : {failed_checks}")

    if failed_checks == 0:
        print("\nOVERALL RESULT: ALL EMAIL RULES TESTS PASSED (100% SUCCESS)")
        print("=" * 80)
        return 0
    else:
        print(f"\nOVERALL RESULT: {failed_checks} CHECK(S) FAILED")
        print("=" * 80)
        return 1


if __name__ == "__main__":
    sys.exit(run_email_rules_suite())
