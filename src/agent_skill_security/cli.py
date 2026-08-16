import argparse
from pathlib import Path

from .scanner import scan_directory
from .report import generate_report



def main():

    parser = argparse.ArgumentParser(
        description="AI Agent Security Scanner"
    )


    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Target directory to scan"
    )


    args = parser.parse_args()


    target = Path(args.path)



    if not target.exists():

        print(
            "Target path does not exist"
        )

        return



    print("=" * 50)

    print(
        "Agent Skill Security Scanner"
    )

    print("=" * 50)


    print()

    print(
        f"Scanning: {target}"
    )


    results = scan_directory(
        str(target)
    )


    report = generate_report(
        results
    )


    print()

    print(report)



if __name__ == "__main__":

    main()
