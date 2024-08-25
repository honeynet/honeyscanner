import argparse
import re
import traceback

from art import ascii_art_honeyscanner
from passive_attacks import HoneypotDetector


def sanitize_string(s: str) -> str:
    """
    Remove special characters from a string and convert it to lowercase.

    Args:
        s (str): The string to sanitize.

    Returns:
        str: The sanitized string.
    """
    s = s.strip()
    s = s.lower()
    s = re.sub(r'[^a-z0-9._\- ]', '', s)
    return s


def parse_arguments() -> argparse.Namespace:
    """
    Creates an argument parser and parses the command-line arguments.

    Returns:
        argparse.Namespace: Parsed arguments object.
    """
    parser = argparse.ArgumentParser(
        description="Honeyscanner: A vulnerability analyzer for honeypots"
    )
    parser.add_argument(
        "--target-ip",
        type=sanitize_string,
        required=True,
        help="The IP address of the honeypot to analyze",
    )
    parser.add_argument(
        "--username",
        type=str,
        required=False,
        default="",
        help="The username to connect to the honeypot",
    )
    parser.add_argument(
        "--password",
        type=str,
        required=False,
        default="",
        help="The password to connect to the honeypot",
    )
    return parser.parse_args()


def main() -> None:
    """
    Main entry point of the program.
    """
    args: argparse.Namespace = parse_arguments()
    print(ascii_art_honeyscanner())
    detector = HoneypotDetector(args.target_ip)
    honeyscanner = detector.detect_honeypot(args.username, args.password)
    if not honeyscanner:
        return

    try:
        honeyscanner.run_all_attacks()
    except Exception:
        issue: str = traceback.format_exc()
        print(f"An error occurred during the attacks: {issue}")
        return

    try:
        honeyscanner.generate_evaluation_report()
    except Exception:
        issue: str = traceback.format_exc()
        print(f"An error occurred during report generation: {issue}")
        return


if __name__ == "__main__":
    main()
