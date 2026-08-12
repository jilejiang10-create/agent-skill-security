from agent_skill_security.scanner import scan_directory


def test_scan_directory():
    result = scan_directory(".")
    assert isinstance(result, dict)
