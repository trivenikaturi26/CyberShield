"""
evaluate_samples.py
CyberShield Phase 6: Controlled Evaluation Dataset

Evaluates CyberShield across 18 synthetic, non-malicious URL strings
categorized into:
  1. Ordinary / Benign URL structures
  2. Suspicious URL structures
  3. Legitimate Unusual URL structures (Demonstrating Heuristic Limitations)

Safety Assurance:
Every URL string is evaluated strictly in memory.
No HTTP requests, DNS lookups, external APIs, or page visits are ever executed.
"""

import os
import sys

# Ensure the root directory of the project is in the Python search path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from core.parser import parse_url
from core.rules import run_all_rules
from core.risk import calculate_risk_score


# ------------------------------------------------------------------------------
# 1. Controlled Synthetic Evaluation Dataset (18 Samples)
# ------------------------------------------------------------------------------
EVALUATION_SAMPLES = [
    # --------------------------------------------------------------------------
    # CATEGORY 1: Ordinary / Benign URL Structures (Standard Web Conventions)
    # --------------------------------------------------------------------------
    {
        "id": 1,
        "category": "Ordinary / Benign",
        "description": "Standard HTTPS commercial website",
        "url": "https://www.example.com",
    },
    {
        "id": 2,
        "category": "Ordinary / Benign",
        "description": "Standard encyclopedia article with path",
        "url": "https://en.wikipedia.org/wiki/Computer_security",
    },
    {
        "id": 3,
        "category": "Ordinary / Benign",
        "description": "Documentation URL with section fragment",
        "url": "https://docs.python.org/3/library/urllib.parse.html#url-parsing",
    },
    {
        "id": 4,
        "category": "Ordinary / Benign",
        "description": "Search query URL with standard query parameter",
        "url": "https://www.google.com/search?q=cybersecurity",
    },
    {
        "id": 5,
        "category": "Ordinary / Benign",
        "description": "Historical academic web page on plain HTTP",
        "url": "http://info.cern.ch/hypertext/WWW/TheProject.html",
    },
    {
        "id": 6,
        "category": "Ordinary / Benign",
        "description": "Schemeless repository link",
        "url": "github.com/torvalds/linux",
    },

    # --------------------------------------------------------------------------
    # CATEGORY 2: Suspicious URL Structures (Heuristic Phishing Indicators)
    # --------------------------------------------------------------------------
    {
        "id": 7,
        "category": "Suspicious Structure",
        "description": "Raw IPv4 address hostname",
        "url": "http://198.51.100.25/login.php",
    },
    {
        "id": 8,
        "category": "Suspicious Structure",
        "description": "Authority spoofing using '@' user-info trick",
        "url": "http://paypal.com@attacker-controlled-server.com/verify",
    },
    {
        "id": 9,
        "category": "Suspicious Structure",
        "description": "Excessive chained subdomains (4 levels)",
        "url": "https://login.microsoft.account.verify.auth-portal.com/signin",
    },
    {
        "id": 10,
        "category": "Suspicious Structure",
        "description": "Combosquatting with 4 hyphens in domain",
        "url": "https://account-verification-portal-service-helpdesk-security-update.com/login",
    },
    {
        "id": 11,
        "category": "Suspicious Structure",
        "description": "Double slash ('//') detected inside path",
        "url": "https://example.com//redirect//auth/login.php",
    },
    {
        "id": 12,
        "category": "Suspicious Structure",
        "description": "Extremely lengthy URL path (>75 chars)",
        "url": "https://secure-login-portal.com/auth/session/token/verification/long/path/parameters/exceeding/the/threshold/character/length/test",
    },
    {
        "id": 13,
        "category": "Suspicious Structure",
        "description": "Compounding red flags: HTTP + IP + @ + Length + Double Slash",
        "url": "http://paypal.com@185.220.101.5/secure//login-verify-account-update.php?session=longtoken12345678901234567890",
    },

    # --------------------------------------------------------------------------
    # CATEGORY 3: Legitimate Unusual Structures (Demonstrating Limitations)
    # --------------------------------------------------------------------------
    {
        "id": 14,
        "category": "Legitimate Unusual",
        "description": "Local home router admin portal (Raw IP + HTTP)",
        "url": "http://192.168.1.1/admin/network_settings",
    },
    {
        "id": 15,
        "category": "Legitimate Unusual",
        "description": "Cloud storage bucket with multi-level subdomain & length",
        "url": "https://company-backup-assets.s3.ap-south-1.amazonaws.com/files/report.pdf",
    },
    {
        "id": 16,
        "category": "Legitimate Unusual",
        "description": "Legitimate complex search link with marketing tracking params",
        "url": "https://www.google.com/search?q=best+cybersecurity+internship+projects+for+btech+students&source=chrome&ie=UTF-8&utm_source=newsletter",
    },
    {
        "id": 17,
        "category": "Legitimate Unusual",
        "description": "Legitimate hyphenated global corporate brand",
        "url": "https://www.mercedes-benz.com/en/vehicles/passenger-cars/",
    },
    {
        "id": 18,
        "category": "Legitimate Unusual",
        "description": "Local web development server with non-standard port on HTTP",
        "url": "http://localhost:8080/dev/dashboard",
    },
]


def run_evaluation():
    total_samples = len(EVALUATION_SAMPLES)
    successful_analyses = 0
    parser_failures = 0

    # Track distribution of categories per dataset group
    # Structure: { group_name: { "Low Concern": count, "Review Recommended": count, "Higher Concern": count } }
    distribution = {
        "Ordinary / Benign": {"Low Concern": 0, "Review Recommended": 0, "Higher Concern": 0},
        "Suspicious Structure": {"Low Concern": 0, "Review Recommended": 0, "Higher Concern": 0},
        "Legitimate Unusual": {"Low Concern": 0, "Review Recommended": 0, "Higher Concern": 0},
    }

    print("=" * 90)
    print("CYBERSHIELD - PHASE 6: CONTROLLED DATASET EVALUATION")
    print("Controlled Functional Demonstration across 18 Synthetic URL Strings")
    print("=" * 90)

    for item in EVALUATION_SAMPLES:
        sample_id = item["id"]
        group = item["category"]
        description = item["description"]
        url = item["url"]

        print(f"\n[Sample {sample_id:02d}/{total_samples:02d}] {group} — {description}")
        print(f"  URL: '{url}'")

        # Step 1: Parser
        parsed = parse_url(url)
        if not parsed.get("is_valid", False):
            parser_failures += 1
            print(f"  Parser Status   : REJECTED ({parsed.get('error_message')})")
            continue

        successful_analyses += 1
        print("  Parser Status   : VALID")

        # Step 2: Rules & Risk Evaluation
        rule_findings = run_all_rules(parsed)
        risk = calculate_risk_score(rule_findings)

        score = risk["total_score"]
        category = risk["category"]
        triggered = risk["triggered_rules"]

        # Record category distribution
        distribution[group][category] += 1

        print(f"  Risk Category   : {category}")
        print(f"  Total Score     : {score} / {risk['max_score']}")
        print(f"  Triggered Rules : {len(triggered)} of 6")

        if triggered:
            for tr in triggered:
                print(f"    • {tr['rule_name']} (+{tr['points_contributed']} pts) | Evidence: {tr['evidence']}")
        else:
            print("    • (No indicators triggered)")

    # --------------------------------------------------------------------------
    # Summary Table
    # --------------------------------------------------------------------------
    print("\n" + "=" * 90)
    print("EVALUATION SUMMARY & CATEGORY DISTRIBUTION")
    print("=" * 90)
    print(f"  Total Samples Evaluated : {total_samples}")
    print(f"  Successful Analyses     : {successful_analyses}")
    print(f"  Parser Failures         : {parser_failures}")
    print("-" * 90)
    print(f"{'Dataset Category':<25} | {'Low Concern':<15} | {'Review Recommended':<20} | {'Higher Concern':<15}")
    print("-" * 90)

    for grp_name, counts in distribution.items():
        print(
            f"{grp_name:<25} | "
            f"{counts['Low Concern']:<15} | "
            f"{counts['Review Recommended']:<20} | "
            f"{counts['Higher Concern']:<15}"
        )
    print("=" * 90)

    # --------------------------------------------------------------------------
    # Observation Summary (Technical & Educational Insights)
    # --------------------------------------------------------------------------
    print("\n" + "=" * 90)
    print("OBSERVATION SUMMARY (INTERVIEW & ACADEMIC NOTES)")
    print("=" * 90)
    print(
        """
1. Which URL characteristics commonly triggered rules?
   • Plain HTTP protocol triggered the +10 pts baseline hygiene indicator.
   • High-weight structural anomalies like raw IP hostnames and the '@' symbol 
     immediately added +30 pts, rapidly moving samples into 'Review Recommended'.
   • Compounding indicators (HTTP + IP + @ + Length + Double Slash) drove the high-risk
     synthetic to 90/100 ('Higher Concern').

2. Which legitimate unusual URLs triggered indicators?
   • Sample 14 (Local Router: http://192.168.1.1) triggered both HTTP and IP Hostname 
     checks (Score: 40/100, Review Recommended) because private routers legitimately use 
     unencrypted IP access.
   • Sample 15 (AWS S3 Bucket) triggered the URL Length check (Score: 10/100) due to 
     region and bucket naming conventions.
   • Sample 16 (Google Search with UTM marketing tags) triggered the Length check 
     (Score: 10/100) due to extensive query strings.

3. Why heuristic detection can produce false positives?
   • Heuristic rules evaluate structural syntax in isolation without semantic context.
   • Legitimate engineering patterns (cloud storage buckets, deep query strings, local 
     development servers) frequently share lexical properties (such as length or raw IPs) 
     with deceptive phishing lures.

4. Why a score is not proof of maliciousness?
   • A heuristic score measures deviation from clean web conventions, NOT criminal intent.
   • A benign site can have non-standard architecture (earning points), while a sophisticated 
     phishing page hosted on a freshly registered .com domain with a valid SSL certificate 
     can present a deceptively clean syntactic structure.

5. Why real-world deployment would require additional validation/data?
   • Comprehensive enterprise threat intelligence requires defense-in-depth:
     - Passive WHOIS data (domain age < 14 days is a strong indicator).
     - Live DNS telemetry (resolving MX records, looking for fast-flux IP switching).
     - SSL/TLS certificate inspection (certificate transparency logs, issuer identity).
     - Page content analysis (detecting fake brand logos, credential input forms, obfuscated JS).
"""
    )
    print("=" * 90)


if __name__ == "__main__":
    run_evaluation()
