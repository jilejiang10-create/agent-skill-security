from agent_skill_security.risk import calculate_risk


def test_calculate_risk():
    findings = [
        {
            "category": "secret",
            "severity": "high"
        }
    ]

    result = calculate_risk(findings)

    assert isinstance(result, dict)
    assert "risk_score" in result
    assert "risk_level" in result
