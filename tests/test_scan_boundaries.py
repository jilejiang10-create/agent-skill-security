from pathlib import Path

import pytest

from agent_skill_security.scanner import ScanPathError, scan_directory


def _finding_names(result):
    return {Path(finding["file"]).name for finding in result["findings"]}


def test_accepts_canonical_inside_path_and_rejects_prefix_confusion(tmp_path):
    root = tmp_path / "allowed"
    inside = root / "nested"
    sibling = tmp_path / "allowed-evil"
    inside.mkdir(parents=True)
    sibling.mkdir()
    (sibling / "bad.py").write_text('os.system("id")', encoding="utf-8")

    result = scan_directory(str(inside / ".."), allowed_root=str(root))
    assert Path(result["target"]) == root.resolve()

    with pytest.raises(ScanPathError, match="outside|allowed"):
        scan_directory(str(root / ".." / "allowed-evil"), allowed_root=str(root))
    with pytest.raises(ScanPathError, match="outside|allowed"):
        scan_directory(str(sibling), allowed_root=str(root))


def test_relative_target_is_resolved_from_allowed_root(tmp_path):
    root = tmp_path / "root"
    nested = root / "nested"
    nested.mkdir(parents=True)
    (nested / "risk.py").write_text('os.system("id")', encoding="utf-8")

    result = scan_directory("nested", allowed_root=str(root))
    assert _finding_names(result) == {"risk.py"}


def test_symlinked_file_cannot_escape_scan_target(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text('os.system("id")', encoding="utf-8")
    link = root / "escape.py"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError) as exc:
        pytest.skip("symlink unavailable: {}".format(exc))

    result = scan_directory(str(root), allowed_root=str(root))
    assert "escape.py" not in _finding_names(result)
    assert result["files_scanned"] == 0
    assert any(
        item["reason"] == "resolved outside scan target"
        for item in result["skipped_files"]
    )

    cli_result = scan_directory(str(root))
    assert "escape.py" in _finding_names(cli_result)
    assert cli_result["files_scanned"] == 1


def test_internal_file_symlink_is_scanned_once(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    real = root / "real.py"
    real.write_text('os.system("id")', encoding="utf-8")
    link = root / "alias.py"
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError) as exc:
        pytest.skip("symlink unavailable: {}".format(exc))

    result = scan_directory(str(root), allowed_root=str(root))
    assert result["files_scanned"] == 1
    assert result["total_issues"] == 1
    assert _finding_names(result) in ({"alias.py"}, {"real.py"})
    assert any(
        item["reason"] == "duplicate resolved file"
        for item in result["skipped_files"]
    )


def test_directory_symlink_cycle_is_pruned(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "risk.py").write_text('os.system("id")', encoding="utf-8")
    loop = root / "loop"
    try:
        loop.symlink_to(root, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip("directory symlink unavailable: {}".format(exc))

    result = scan_directory(str(root), allowed_root=str(root))
    assert result["files_scanned"] == 1
    assert result["total_issues"] == 1


def test_symlinked_target_cannot_escape_allowed_root(tmp_path):
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    link = root / "escape"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip("directory symlink unavailable: {}".format(exc))

    with pytest.raises(ScanPathError, match="outside|allowed"):
        scan_directory(str(link), allowed_root=str(root))


def test_cli_style_scan_remains_unconfined(tmp_path):
    web_root = tmp_path / "web"
    outside = tmp_path / "outside"
    web_root.mkdir()
    outside.mkdir()
    (outside / "risk.py").write_text('os.system("id")', encoding="utf-8")

    result = scan_directory(str(outside))
    assert "risk.py" in _finding_names(result)

    with pytest.raises(ScanPathError, match="outside|allowed"):
        scan_directory(str(outside), allowed_root=str(web_root))


def test_large_file_is_skipped_but_nul_content_cannot_bypass_scan(tmp_path):
    (tmp_path / "small.py").write_text('os.system("id")', encoding="utf-8")
    (tmp_path / "large.py").write_text(
        "x" * 256 + '\nsubprocess.run(["id"])', encoding="utf-8"
    )
    (tmp_path / "binary.py").write_bytes(
        b'\x00\x01api_key="sk-AbCdEf0123456789GhIjKlMn"'
    )

    limited = scan_directory(
        str(tmp_path), allowed_root=str(tmp_path), max_file_size=64
    )
    assert "small.py" in _finding_names(limited)
    assert "large.py" not in _finding_names(limited)
    assert "binary.py" in _finding_names(limited)
    assert limited["files_scanned"] == 2
    assert "sk-AbCdEf0123456789GhIjKlMn" not in repr(limited)

    full = scan_directory(
        str(tmp_path), allowed_root=str(tmp_path), max_file_size=1024
    )
    assert {"small.py", "large.py", "binary.py"} <= _finding_names(full)
    assert full["files_scanned"] == 3


def test_max_files_stops_after_deterministic_budget(tmp_path):
    for name in ("a.py", "b.py", "c.py"):
        (tmp_path / name).write_text('os.system("id")', encoding="utf-8")

    result = scan_directory(str(tmp_path), max_files=2)
    assert result["files_scanned"] == 2
    assert result["files_seen"] == 2
    assert _finding_names(result) == {"a.py", "b.py"}
    assert any(
        item["reason"] == "maximum file count reached"
        for item in result["skipped_files"]
    )


def test_max_files_counts_skipped_entries(tmp_path):
    for name in ("a.py", "b.py", "c.py"):
        (tmp_path / name).write_text("x" * 100, encoding="utf-8")

    result = scan_directory(str(tmp_path), max_file_size=1, max_files=2)
    assert result["files_seen"] == 2
    assert result["files_scanned"] == 0
    assert any(
        item["reason"] == "maximum file count reached"
        for item in result["skipped_files"]
    )


def test_finding_limit_cannot_hide_later_risk_categories(tmp_path):
    (tmp_path / "dense.txt").write_text(
        "jailbreak\n" * 100
        + 'api_key = "sk-AbCdEf0123456789GhIjKlMn"\n'
        + 'os.system("id")',
        encoding="utf-8",
    )

    result = scan_directory(str(tmp_path), max_findings_per_file=3)
    categories = {finding["category"] for finding in result["findings"]}
    assert {"prompt_injection", "hardcoded_api_key", "dangerous_shell"} <= categories
    assert result["risk"]["risk_score"] == 90
    assert result["risk"]["risk_level"] == "CRITICAL"
    assert result["truncated_files"] == [
        {"file": "dense.txt", "reason": "finding limit reached"}
    ]


def test_invalid_targets_and_limits_are_rejected(tmp_path):
    file_target = tmp_path / "file.py"
    file_target.write_text("clean", encoding="utf-8")

    with pytest.raises(ScanPathError, match="does not exist"):
        scan_directory(str(tmp_path / "missing"))
    with pytest.raises(ScanPathError, match="not a directory"):
        scan_directory(str(file_target))
    with pytest.raises(ValueError, match="max_file_size"):
        scan_directory(str(tmp_path), max_file_size=-1)
    with pytest.raises(ValueError, match="max_files"):
        scan_directory(str(tmp_path), max_files=0)
    with pytest.raises(ValueError, match="max_findings_per_file"):
        scan_directory(str(tmp_path), max_findings_per_file=0)
