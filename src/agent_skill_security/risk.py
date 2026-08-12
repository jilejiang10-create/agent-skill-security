from typing import List, Dict


RISK_WEIGHTS = {
    "hardcoded_api_key": 40,
    "dangerous_shell": 35,
    "network_request": 20,
    "file_system_write": 25,
    "prompt_injection": 45,
}


def calculate_risk(findings: List[Dict]) -> Dict:
    """
    Calculate AI agent security risk score.
    """

    score = 0
    categories = []


    for item in findings:

        category = item.get("category")


        if category in RISK_WEIGHTS:

            score += RISK_WEIGHTS[category]

            categories.append(category)



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
