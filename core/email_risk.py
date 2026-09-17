"""
core/email_risk.py
CyberShield: Explainable Phishing URL & Email Security Analyzer

Email Risk Assessment Engine
Combines individual heuristic findings from core/email_rules.py and
the existing URL analyzer into a deterministic, explainable risk score (0–100)
and risk tier classification.

Key Principles:
    - Strictly deterministic and reproducible.
    - Zero network requests. No machine learning or black-box models.
    - Scores are bounded strictly between 0 and 100.
    - Transparent explanations and point attribution for every triggered check.
"""

from typing import Any, Optional


MAX_POSSIBLE_SCORE = 100

# Deterministic rule weights mapped to exact rule names from core/email_rules.py
EMAIL_RULE_WEIGHTS = {
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

HEURISTIC_EMAIL_DISCLAIMER = (
    "The email risk score is a heuristic indicator-based assessment. "
    "It does not prove that an email is malicious and is not an AI probability of phishing."
)


def get_email_risk_category(score: int) -> tuple[str, str]:
    """
    Maps an integer score (0-100) to a continuous risk category and explanation.

    Threshold Ranges:
      0  - 20 : Low Concern (🟢)
      21 - 59 : Review Recommended (🟠)
      60 - 100: Higher Concern (🔴)
    """
    if score <= 20:
        category = "Low Concern"
        description = (
            "No strong deceptive or social engineering indicators detected. "
            "The email conforms to standard communication conventions."
        )
    elif score <= 59:
        category = "Review Recommended"
        description = (
            "Several non-standard or mildly coercive indicators detected. "
            "Manual review of sender identity and linked destinations is recommended."
        )
    else:
        category = "Higher Concern"
        description = (
            "Multiple strong phishing indicators detected, such as credential solicitation, "
            "severe threats, display spoofing, or high-risk embedded links."
        )

    return category, description


def calculate_email_risk_score(
    rule_findings: list[dict[str, Any]],
    analyzed_urls: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    """
    Aggregates the email rule findings into a weighted score (0–100).
    Integrates results from the existing URL analyzer.

    Args:
        rule_findings: List of rule result dictionaries from core/email_rules.py.
        analyzed_urls: Optional list of URL assessment dictionaries produced by
                       the existing core/risk.py pipeline.

    Returns:
        dict: A structured dictionary containing:
            total_score: int (0-100, clamped)
            max_score: int (100)
            category: str ("Low Concern", "Review Recommended", "Higher Concern")
            category_description: str
            triggered_rules: list of dicts for rules that triggered
            explanations: list of explanation strings
            analyzed_urls: list of individual URL analysis summaries
            highest_url_score: int
            disclaimer: str
    """
    total_score = 0
    triggered_rules = []
    explanations = []

    # Handle empty or invalid rule findings safely
    if not rule_findings or not isinstance(rule_findings, list):
        category, desc = get_email_risk_category(0)
        return {
            "total_score": 0,
            "max_score": MAX_POSSIBLE_SCORE,
            "category": category,
            "category_description": desc,
            "triggered_rules": [],
            "explanations": ["No email rules were evaluated."],
            "analyzed_urls": analyzed_urls or [],
            "highest_url_score": 0,
            "disclaimer": HEURISTIC_EMAIL_DISCLAIMER,
        }

    # Evaluate each rule finding
    for finding in rule_findings:
        rule_name = finding.get("rule_name", "Unknown Rule")
        is_triggered = finding.get("triggered", False)
        explanation = finding.get("explanation", "")
        evidence = finding.get("evidence", "")

        weight = EMAIL_RULE_WEIGHTS.get(rule_name, 0)

        if is_triggered:
            total_score += weight
            triggered_rules.append({
                "rule_name": rule_name,
                "points_contributed": weight,
                "explanation": explanation,
                "evidence": evidence,
            })
            explanations.append(f"[{rule_name} (+{weight} pts)]: {explanation}")

    # Inspect analyzed URLs for highest risk
    highest_url_score = 0
    if analyzed_urls:
        for u in analyzed_urls:
            u_score = u.get("total_score", 0)
            if u_score > highest_url_score:
                highest_url_score = u_score

    # Score clamping to strictly 0-100
    clamped_score = max(0, min(total_score, MAX_POSSIBLE_SCORE))

    # Determine risk category
    category, category_description = get_email_risk_category(clamped_score)

    return {
        "total_score": clamped_score,
        "max_score": MAX_POSSIBLE_SCORE,
        "category": category,
        "category_description": category_description,
        "triggered_rules": triggered_rules,
        "explanations": explanations if explanations else ["All evaluated email rules passed without triggers."],
        "analyzed_urls": analyzed_urls or [],
        "highest_url_score": highest_url_score,
        "disclaimer": HEURISTIC_EMAIL_DISCLAIMER,
    }
