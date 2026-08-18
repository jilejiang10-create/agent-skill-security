RISK_WEIGHTS = {

    "hardcoded_api_key": 40,

    "secret_exposure": 40,

    "dangerous_shell": 30,

    "dangerous_code": 30,

    "file_system_write": 20,

    "prompt_injection": 20,

    "network_request": 10,

}



def calculate_risk(findings):

    if not findings:

        return {

            "risk_score": 0,

            "risk_level": "LOW",

            "categories": []

        }



    score = 0

    categories = set()



    for item in findings:


        if not isinstance(item, dict):

            continue



        category = (
            item.get("category")
            or item.get("type")
            or "unknown"
        )



        categories.add(category)



        score += RISK_WEIGHTS.get(
            category,
            10
        )



    # 最大100分

    score = min(
        score,
        100
    )



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

        "categories": list(categories)

    }