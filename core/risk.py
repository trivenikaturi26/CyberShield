"""
core/risk.py
CyberShield: Explainable Phishing URL Security Analyzer

Phase 3: Transparent Risk Assessment Module
This module combines the individual heuristic findings from core/rules.py
into a deterministic, weighted risk score and categorical assessment.

Key Principles:
- Strictly deterministic and reproducible.
- Zero network requests.
- No machine learning or external APIs.
- Does not claim to prove maliciousness or calculate phishing probability.
- All scores are bounded between 0 and 100.
"""

# Maximum possible score achievable
MAX_POSSIBLE_SCORE = 100

# Deterministic rule weights mapped to exact rule names from core/rules.py
RULE_WEIGHTS = {
    "IP Address Hostname Check": 30,
    "@ Symbol User-Info Check": 30,
    "Excessive Subdomain Check": 10,
    "Suspicious Character & Pattern Check": 10,
    "URL Length Check": 10,
    "HTTPS Usage Check": 10,
}

# Standard ethical and technical security disclaimer
HEURISTIC_DISCLAIMER = (
    "The score is a heuristic indicator-based assessment. "
    "It does not prove that a URL is malicious and is not a probability of phishing."
)


def get_risk_category(score: int) -> tuple[str, str]:
    """
    Maps an integer score (0-100) to a continuous risk category and explanation.

    Threshold Ranges:
      0  - 20 : Low Concern
      21 - 59 : Review Recommended
      60 - 100: Higher Concern
    """
    if score <= 20:
        category = "Low Concern"
        description = (
            "No strong suspicious lexical patterns detected. "
            "The URL structure conforms to standard web conventions."
        )
    elif score <= 59:
        category = "Review Recommended"
        description = (
            "Several anomalous or non-standard characteristics detected. "
            "Manual review of the root domain is recommended before interacting."
        )
    else:
        category = "Higher Concern"
        description = (
            "Multiple strong suspicious indicators detected, "
            "including one or more high-weight structural indicators."
        )

    return category, description


def calculate_risk_score(rule_findings: list[dict]) -> dict:
    """
    Aggregates a list of rule findings produced by core/rules.py.

    Args:
        rule_findings: List of rule result dictionaries from core/rules.py.
                       Each item must have: 'rule_name', 'triggered', 'explanation', 'evidence'.

    Returns:
        dict: A structured dictionary containing:
            total_score: int (0-100)
            max_score: int (100)
            category: str ("Low Concern", "Review Recommended", "Higher Concern")
            category_description: str
            triggered_rules: list of dicts for rules that triggered
            explanations: list of explanation strings for triggered rules
            disclaimer: str
    """
    total_score = 0
    triggered_rules = []
    explanations = []

    # Handle empty or invalid input safely
    if not rule_findings or not isinstance(rule_findings, list):
        category, desc = get_risk_category(0)
        return {
            "total_score": 0,
            "max_score": MAX_POSSIBLE_SCORE,
            "category": category,
            "category_description": desc,
            "triggered_rules": [],
            "explanations": ["No rules were evaluated."],
            "disclaimer": HEURISTIC_DISCLAIMER,
        }

    # Evaluate each rule finding
    for finding in rule_findings:
        rule_name = finding.get("rule_name", "Unknown Rule")
        is_triggered = finding.get("triggered", False)
        explanation = finding.get("explanation", "")
        evidence = finding.get("evidence", "")

        # Lookup the weight assigned to this rule (defaults to 0 if unknown)
        weight = RULE_WEIGHTS.get(rule_name, 0)

        # Only accumulate points if the rule indicator was triggered
        if is_triggered:
            total_score += weight
            triggered_rules.append({
                "rule_name": rule_name,
                "points_contributed": weight,
                "explanation": explanation,
                "evidence": evidence,
            })
            explanations.append(f"[{rule_name} (+{weight} pts)]: {explanation}")

    # Ensure score is strictly clamped between 0 and 100
    clamped_score = max(0, min(total_score, MAX_POSSIBLE_SCORE))

    # Map the cumulative score to its continuous category
    category, category_description = get_risk_category(clamped_score)

    return {
        "total_score": clamped_score,
        "max_score": MAX_POSSIBLE_SCORE,
        "category": category,
        "category_description": category_description,
        "triggered_rules": triggered_rules,
        "explanations": explanations if explanations else ["All evaluated rules passed without triggers."],
        "disclaimer": HEURISTIC_DISCLAIMER,
    }
