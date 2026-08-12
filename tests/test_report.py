from agent_skill_security.report import generate_report


def test_generate_report():
    results = {
        "test.py": {
            "findings": [
                {
                    "category": "secret",
                    "match": "API_KEY"
                }
            ],
            "risk": 80
        }
    }

    report = generate_report(results)

    assert isinstance(report, str)
    assert "Risk" in report
