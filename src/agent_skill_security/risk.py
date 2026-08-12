from typing import List, Dict


RISK_WEIGHTS = {
    "hardcoded_api_key": 30,
    "dangerous_shell": 25,
    "network_request": 15,
    "file_system_write": 20,
    "prompt_injection": 35,
}


def calculate_risk(findings: List[Dict]) -> Dict:
    """
    Calculate security risk score.

    findings example:
    [
        {
            "category": "prompt_injection",
            "match": "ignore previous instructions"
        }
    ]
    """

    score = 0
    categories = []

    for item in findings:
        category = item.get("category")

        if category in RISK_WEIGHTS:
            score += RISK_WEIGHTS[category]
            categories.append(category)

    # limit score max 100
    score = min(score, 100)

    if score >= 80:
        level = "critical"
    elif score >= 50:
        level = "high"
    elif score >= 20:
        level = "medium"
    else:
        level = "low"

    return {
        "risk_score": score,
        "risk_level": level,
        "issues": categories
    }
