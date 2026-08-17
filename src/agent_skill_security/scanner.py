"""Filesystem scanner with optional Web-safe path confinement."""

import os
from pathlib import Path
from typing import Dict, List, Optional, Union

from agent_skill_security.risk import calculate_risk
from agent_skill_security.rules import (
    RULE_PATTERNS,
    safe_display_text,
    scan_text,
    scan_text_with_metadata,
)


SCHEMA_VERSION = "1.0"
IGNORE_DIRS = {".git", "__pycache__", ".pytest_cache", ".venv", "venv"}

# Backwards-compatible export. The registry is owned and executed by rules.py.
DANGEROUS_PATTERNS = RULE_PATTERNS


class ScanPathError(ValueError):
    """Raised when a scan target is invalid or outside its allowed root."""


class _FileTooLargeError(ValueError):
    pass


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _resolve_existing(path: Path, label: str) -> Path:
    try:
        return path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ScanPathError("{} does not exist or cannot be resolved".format(label)) from exc


def _resolve_allowed_root(allowed_root: Union[str, Path]) -> Path:
    root = _resolve_existing(Path(allowed_root).expanduser(), "Allowed scan root")
    if not root.is_dir():
        raise ScanPathError("Allowed scan root is not a directory")
    return root


def _resolve_directory(
    directory: Union[str, Path],
    allowed_root: Optional[Union[str, Path]],
) -> Path:
    requested = Path(directory).expanduser()
    boundary = None

    if allowed_root is not None:
        boundary = _resolve_allowed_root(allowed_root)
        if not requested.is_absolute():
            requested = boundary / requested

        # Reject obvious external, cross-drive, and UNC targets before strict
        # resolution can touch metadata outside the administrator's boundary.
        lexical_target = Path(os.path.abspath(str(requested)))
        if not _is_within(lexical_target, boundary):
            raise ScanPathError("Scan target is outside the allowed scan root")

    target = _resolve_existing(requested, "Scan target")
    if not target.is_dir():
        raise ScanPathError("Scan target is not a directory")

    if boundary is not None and not _is_within(target, boundary):
        raise ScanPathError("Scan target is outside the allowed scan root")

    return target


def _display_path(path: Path, root: Path) -> str:
    try:
        display = path.relative_to(root).as_posix()
    except ValueError:
        display = str(path)
    return safe_display_text(display)


def _read_text_file(path: Path, max_bytes: Optional[int] = None) -> str:
    with path.open("rb") as stream:
        data = stream.read() if max_bytes is None else stream.read(max_bytes + 1)
    if max_bytes is not None and len(data) > max_bytes:
        raise _FileTooLargeError("file exceeds size limit")
    return data.decode("utf-8", errors="ignore")


def scan_file(
    path: str,
    *,
    allowed_root: Optional[Union[str, Path]] = None,
    display_path: Optional[str] = None,
) -> List[Dict[str, object]]:
    """Scan one regular text file.

    Existing callers retain the original list-returning API. Pass
    ``allowed_root`` only for a confined interface such as the Web dashboard.
    """

    requested = Path(path).expanduser()
    boundary = None
    if allowed_root is not None:
        boundary = _resolve_allowed_root(allowed_root)
        if not requested.is_absolute():
            requested = boundary / requested
        lexical_file = Path(os.path.abspath(str(requested)))
        if not _is_within(lexical_file, boundary):
            raise ScanPathError("Scan file is outside the allowed scan root")

    try:
        resolved = requested.resolve(strict=True)
    except (OSError, RuntimeError):
        return []

    if boundary is not None and not _is_within(resolved, boundary):
        raise ScanPathError("Scan file is outside the allowed scan root")
    if not resolved.is_file():
        return []

    try:
        content = _read_text_file(resolved)
    except OSError:
        return []

    source = safe_display_text(display_path if display_path is not None else requested)
    return scan_text(content, source=source)


def _validate_limits(
    max_file_size: Optional[int],
    max_files: Optional[int],
    max_findings_per_file: Optional[int],
) -> None:
    if max_file_size is not None and (
        not isinstance(max_file_size, int) or isinstance(max_file_size, bool) or max_file_size < 0
    ):
        raise ValueError("max_file_size must be a non-negative integer or None")
    if max_files is not None and (
        not isinstance(max_files, int) or isinstance(max_files, bool) or max_files < 1
    ):
        raise ValueError("max_files must be a positive integer or None")
    if max_findings_per_file is not None and (
        not isinstance(max_findings_per_file, int)
        or isinstance(max_findings_per_file, bool)
        or max_findings_per_file < 1
    ):
        raise ValueError("max_findings_per_file must be a positive integer or None")


def scan_directory(
    directory: str,
    *,
    allowed_root: Optional[Union[str, Path]] = None,
    max_file_size: Optional[int] = None,
    max_files: Optional[int] = None,
    max_findings_per_file: Optional[int] = None,
) -> Dict[str, object]:
    """Scan a directory and return the canonical ScanResult structure.

    CLI callers omit ``allowed_root`` and can scan any local directory. The Web
    interface passes it so path traversal, prefix confusion, cross-drive paths,
    and escaping links are rejected or skipped.
    """

    _validate_limits(max_file_size, max_files, max_findings_per_file)
    root = _resolve_directory(directory, allowed_root)

    findings: List[Dict[str, object]] = []
    skipped_files: List[Dict[str, str]] = []
    truncated_files: List[Dict[str, str]] = []
    scan_errors: List[Dict[str, str]] = []
    files_scanned = 0
    files_seen = 0
    limit_reached = False
    confined = allowed_root is not None
    seen_directories = {root}
    seen_files = set()

    def record_walk_error(error: OSError) -> None:
        error_path = Path(error.filename) if error.filename else root
        scan_errors.append(
            {
                "file": _display_path(error_path, root),
                "error": error.__class__.__name__,
            }
        )

    for current_name, dirnames, filenames in os.walk(
        str(root), topdown=True, followlinks=False, onerror=record_walk_error
    ):
        current = Path(current_name)
        dirnames.sort()
        filenames.sort()

        for dirname in list(dirnames):
            directory_path = current / dirname
            relative = _display_path(directory_path, root)

            if dirname in IGNORE_DIRS:
                dirnames.remove(dirname)
                continue
            if directory_path.is_symlink():
                dirnames.remove(dirname)
                skipped_files.append({"file": relative, "reason": "symbolic link"})
                continue

            try:
                resolved_directory = directory_path.resolve(strict=True)
            except (OSError, RuntimeError) as exc:
                dirnames.remove(dirname)
                scan_errors.append(
                    {"file": relative, "error": exc.__class__.__name__}
                )
                continue

            if not _is_within(resolved_directory, root):
                dirnames.remove(dirname)
                skipped_files.append(
                    {"file": relative, "reason": "resolved outside scan target"}
                )
                continue
            if resolved_directory in seen_directories:
                dirnames.remove(dirname)
                skipped_files.append(
                    {"file": relative, "reason": "duplicate or cyclic directory"}
                )
                continue
            seen_directories.add(resolved_directory)

        for filename in filenames:
            if max_files is not None and files_seen >= max_files:
                skipped_files.append(
                    {"file": "*", "reason": "maximum file count reached"}
                )
                limit_reached = True
                break
            files_seen += 1

            lexical_path = current / filename
            relative = _display_path(lexical_path, root)

            try:
                resolved_path = lexical_path.resolve(strict=True)
            except (OSError, RuntimeError) as exc:
                scan_errors.append(
                    {"file": relative, "error": exc.__class__.__name__}
                )
                continue

            if confined and not _is_within(resolved_path, root):
                skipped_files.append(
                    {"file": relative, "reason": "resolved outside scan target"}
                )
                continue
            if not resolved_path.is_file():
                skipped_files.append({"file": relative, "reason": "not a regular file"})
                continue
            if resolved_path in seen_files:
                skipped_files.append(
                    {"file": relative, "reason": "duplicate resolved file"}
                )
                continue
            seen_files.add(resolved_path)

            try:
                content = _read_text_file(resolved_path, max_file_size)
            except _FileTooLargeError:
                skipped_files.append(
                    {"file": relative, "reason": "file exceeds size limit"}
                )
                continue
            except OSError as exc:
                scan_errors.append(
                    {"file": relative, "error": exc.__class__.__name__}
                )
                continue

            file_findings, truncated = scan_text_with_metadata(
                content,
                source=relative,
                max_findings=max_findings_per_file,
            )
            findings.extend(file_findings)
            if truncated:
                truncated_files.append(
                    {"file": relative, "reason": "finding limit reached"}
                )
            files_scanned += 1

        if limit_reached:
            break

    findings.sort(
        key=lambda item: (
            str(item["file"]),
            int(item["line"]),
            int(item["column"]),
            str(item["rule_id"]),
        )
    )
    risk = calculate_risk(findings)
    complete_skip_reasons = {"duplicate resolved file", "duplicate or cyclic directory"}
    coverage_skips = [
        item
        for item in skipped_files
        if item.get("reason") not in complete_skip_reasons
    ]
    scan_complete = not coverage_skips and not truncated_files and not scan_errors

    return {
        "schema_version": SCHEMA_VERSION,
        "target": safe_display_text(root),
        "scan_complete": scan_complete,
        "files_seen": files_seen,
        "files_scanned": files_scanned,
        "skipped_files": skipped_files,
        "truncated_files": truncated_files,
        "scan_errors": scan_errors,
        "findings": findings,
        "total_issues": len(findings),
        "risk": risk,
    }
