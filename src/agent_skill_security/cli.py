import argparse
from pathlib import Path

from .scanner import scan_directory


def main():
    parser = argparse.ArgumentParser(
        description="AI Agent Security Scanner"
    )

    parser.add_argument(
        "path",
        help="Target directory to scan"
    )

    args = parser.parse_args()

    target = Path(args.path)

    if not target.exists():
        print("Target path does not exist")
        return

    results = scan_directory(str(target))

    if not results:
        print("No security issues found.")
        return

    print("\nSecurity findings:\n")

    for file_name, findings in results.items():
        print(f"[FILE] {file_name}")

        for finding in findings:
            print(
                f"- {finding['category']}: "
                f"{finding['match']}"
            )


if __name__ == "__main__":
    main()
