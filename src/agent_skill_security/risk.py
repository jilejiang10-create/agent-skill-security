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


    seen_categories = set()
    
    for item in findings:
    
        category = (
            item.get("category")
            or item.get("type")
        )
    
        if category in RISK_WEIGHTS:
    
            # 同类型只计算一次
            if category not in seen_categories:
                score += RISK_WEIGHTS[category]
                seen_categories.add(category)
    
                categories.append(category)



    score = min(score, 100)


    if score >= 80:
        level = "CRITICAL"
    
    elif score >= 40:
        level = "HIGH"
    
    elif score >= 15:
        level = "MEDIUM"
    
    else:
        level = "LOW"



    return {
        "risk_score": score,
        "risk_level": level,
        "issues": categories
    }
