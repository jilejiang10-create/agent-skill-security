from pathlib import Path
from .scanner import scan_directory
from .report import generate_report


def run_dashboard(target="."):
    print("=" * 50)
    print("Agent Skill Security Dashboard")
    print("=" * 50)

    print("\nScanning:", target)

    results = scan_directory(target)

    report = generate_report(results)

    print("\nSecurity Report")
    print("-" * 50)

    print(report)


if __name__ == "__main__":
    run_dashboard()
