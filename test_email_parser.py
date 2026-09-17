"""
test_email_parser.py
CyberShield: Explainable Phishing URL & Email Security Analyzer

Automated Verification Test Suite for core/email_parser.py
Verifies static email decomposition, sender parsing, URL extraction,
attachment detection, text statistics, and empty input handling.
"""

import os
import sys

# Ensure the project root directory is in the Python module search path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from core.email_parser import parse_email, extract_urls_from_text, extract_attachment_references, parse_sender_info


def run_email_parser_suite() -> int:
    print("=" * 80)
    print("CYBERSHIELD: EMAIL PARSER VERIFICATION TEST SUITE")
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
    # 1. Standard Benign Email Parsing
    # --------------------------------------------------------------------------
    print("\n--- TEST 1: Standard Benign Email ---")
    sender = "Tech Support <support@company.org>"
    subject = "Scheduled Maintenance Notice"
    body = "Hello team, please be advised that our internal portal at https://company.org/status will undergo maintenance."
    
    parsed = parse_email(sender, subject, body)
    record_check("Valid status flag", parsed["is_valid"] is True)
    record_check("Sender display name extracted", parsed["sender_display_name"] == "Tech Support")
    record_check("Sender email address normalized", parsed["sender_email"] == "support@company.org")
    record_check("Sender domain extracted", parsed["sender_domain"] == "company.org")
    record_check("Sender is not malformed", parsed["is_sender_malformed"] is False)
    record_check("URL extracted from body", "https://company.org/status" in parsed["extracted_urls"])
    record_check("URL count matches", parsed["url_count"] == 1)

    # --------------------------------------------------------------------------
    # 2. Sender Address Parsing Variations
    # --------------------------------------------------------------------------
    print("\n--- TEST 2: Sender Parsing Variations ---")
    # Bare email
    bare = parse_sender_info("alice@example.com")
    record_check("Bare email parsed", bare["email"] == "alice@example.com" and bare["domain"] == "example.com")

    # Malformed email without @
    malformed = parse_sender_info("invalid_sender_string")
    record_check("Malformed sender flagged", malformed["is_malformed"] is True)

    # IP address domain
    ip_sender = parse_sender_info("admin@192.168.1.1")
    record_check("IP domain captured", ip_sender["domain"] == "192.168.1.1")

    # --------------------------------------------------------------------------
    # 3. URL Extraction & Normalization
    # --------------------------------------------------------------------------
    print("\n--- TEST 3: URL Extraction & Normalization ---")
    sample_text = (
        "Check this link: https://portal.example.com/login. "
        "Also visit www.backup-site.org/index.html, and defanged hxxps://secure[.]bank[.]com/verify."
    )
    urls = extract_urls_from_text(sample_text)
    record_check("Extracted multiple URLs", len(urls) >= 3, f"Got {len(urls)}")
    record_check("Trailing period removed from URL", "https://portal.example.com/login" in urls)
    record_check("Defanged URL normalized", any("secure.bank.com" in u for u in urls))

    # --------------------------------------------------------------------------
    # 4. Attachment Reference Extraction
    # --------------------------------------------------------------------------
    print("\n--- TEST 4: Attachment Reference Extraction ---")
    body_with_files = (
        "Please find your invoice attached as invoice_march_2026.pdf.exe. "
        "Also do not execute patch_update.bat or setup.scr. Read readme.txt for info."
    )
    attachments = extract_attachment_references(body_with_files)
    record_check("Found .exe attachment", any(".exe" in a for a in attachments))
    record_check("Found .bat attachment", any(".bat" in a for a in attachments))
    record_check("Found .scr attachment", any(".scr" in a for a in attachments))
    record_check("Ignored benign .txt file", not any("readme.txt" in a for a in attachments))

    # --------------------------------------------------------------------------
    # 5. Text Statistics Computation
    # --------------------------------------------------------------------------
    print("\n--- TEST 5: Lexical Statistics ---")
    shouting_parsed = parse_email(
        sender="alert@notice.com",
        subject="URGENT ACTION REQUIRED!!!",
        body="PLEASE VERIFY IMMEDIATELY! DO NOT DELAY!"
    )
    stats = shouting_parsed["basic_stats"]
    record_check("Word count computed", stats["word_count"] > 0)
    record_check("Exclamation count detected", stats["exclamation_count"] >= 4, f"Got {stats['exclamation_count']}")
    record_check("Uppercase ratio high", stats["uppercase_ratio"] > 0.5, f"Got {stats['uppercase_ratio']}")

    # --------------------------------------------------------------------------
    # 6. Empty / Invalid Input Handling
    # --------------------------------------------------------------------------
    print("\n--- TEST 6: Empty Input Handling ---")
    empty_parsed = parse_email("", "", "")
    record_check("Empty email marked invalid", empty_parsed["is_valid"] is False)
    record_check("Helpful error message provided", len(empty_parsed["error_message"]) > 0)
    record_check("Safe default values returned", empty_parsed["url_count"] == 0 and empty_parsed["extracted_urls"] == [])

    # --------------------------------------------------------------------------
    # Final Summary
    # --------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("EMAIL PARSER TEST SUMMARY")
    print("=" * 80)
    print(f"  Total Checks Executed : {total_checks}")
    print(f"  Passed Checks         : {passed_checks}")
    print(f"  Failed Checks         : {failed_checks}")

    if failed_checks == 0:
        print("\nOVERALL RESULT: ALL EMAIL PARSER TESTS PASSED (100% SUCCESS)")
        print("=" * 80)
        return 0
    else:
        print(f"\nOVERALL RESULT: {failed_checks} CHECK(S) FAILED")
        print("=" * 80)
        return 1


if __name__ == "__main__":
    sys.exit(run_email_parser_suite())
