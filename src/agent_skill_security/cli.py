import argparse
from pathlib import Path

from . import __version__
from .report import generate_report
from .rules import safe_display_text
from .scanner import ScanPathError, scan_directory



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

    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s {}".format(__version__),
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
        "Scanning: {}".format(safe_display_text(target))
    )


    try:
        results = scan_directory(
            str(target)
        )
    except ScanPathError as exc:
        print(
            "Scanner error: {}".format(exc)
        )
        return


    report = generate_report(
        results
    )


    print()

    print(report)



if __name__ == "__main__":

    main()
