from agent_skill_security.risk import calculate_risk


def test_calculate_risk():
    findings = [
        {
            "category": "secret",
            "severity": "high"
        }
    ]

    result = calculate_risk(findings)

    assert isinstance(result, int)
    assert result > 0
