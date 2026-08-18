from .cli import main


if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print("\nScan cancelled.")

    except Exception as e:

        print(
            f"Error: {e}"
        )
