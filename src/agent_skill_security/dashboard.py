import argparse

from .scanner import scan_directory
from .report import generate_report



def run_dashboard(target="."):

    print("=" * 60)

    print("Agent Skill Security Dashboard")

    print("=" * 60)


    print()

    print(
        f"Scanning Target: {target}"
    )


    print("-" * 60)



    try:

        results = scan_directory(target)


        report = generate_report(results)



        print()

        print("Security Report")

        print("-" * 60)



        print(report)



    except Exception as e:


        print()

        print(
            "Scanner Error:"
        )

        print(e)



        return False



    return True





def main():


    parser = argparse.ArgumentParser(

        description="AI Agent Security Scanner"

    )


    parser.add_argument(

        "target",

        nargs="?",

        default=".",

        help="Directory to scan"

    )



    args = parser.parse_args()



    run_dashboard(
        args.target
    )





if __name__ == "__main__":

    main()
