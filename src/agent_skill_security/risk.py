from typing import List, Dict


RISK_WEIGHTS = {

    # 密钥泄露
    "secret_exposure": 35,

    # 明文 API Key
    "hardcoded_api_key": 35,

    # 危险命令执行
    "dangerous_shell": 30,

    # 网络请求风险
    "network_request": 15,

    # 文件写入风险
    "file_system_write": 15,

    # Prompt 注入
    "prompt_injection": 25,
}



def calculate_risk(findings: List[Dict]) -> Dict:
    """
    Calculate AI agent security risk score.
    
    Returns:
        risk_score:
            0-100 security risk score

        risk_level:
            LOW
            MEDIUM
            HIGH
            CRITICAL
    """


    score = 0

    categories = []

    seen_categories = set()


    for item in findings:

        category = (
            item.get("category")
            or item.get("type")
        )


        if not category:
            continue



        if category in RISK_WEIGHTS:


            # 同类风险只计算一次
            if category not in seen_categories:

                score += RISK_WEIGHTS[category]

                seen_categories.add(category)

                categories.append(category)



    score = min(score,100)



    if score >= 80:

        level = "CRITICAL"


    elif score >= 50:

        level = "HIGH"


    elif score >= 20:

        level = "MEDIUM"


    else:

        level = "LOW"



    return {

        "risk_score": score,

        "risk_level": level,

        "issues": categories,

        "total_findings": len(findings)

    }
