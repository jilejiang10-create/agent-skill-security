import json



def generate_json_report(results):

    return json.dumps(
        results,
        indent=4,
        ensure_ascii=False
    )