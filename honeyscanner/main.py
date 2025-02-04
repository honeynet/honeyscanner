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
        description="Honeyscanner: A vulnerability analyzer for honeypots",
        formatter_class=argparse.RawTextHelpFormatter
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
    parser.add_argument(
        "--attack",
        type=str,
        required=False,
        default="all",
        help="The attack to perform on the honeypot.\nVulnAnalyzer:vulnanalyze\nStaticHoney:statichoney\nTrivyScanner:trivyscanner\nDoS:dos\nFuzzing:fuzz\nTarBomb:tarbomb"
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

    #attack to perform
    attack = args.attack

    if not honeyscanner:
        return

    try:
        if attack=="vulnanalyze":
            honeyscanner.run_vulnanalyzer()
        elif attack=="statichoney":
            honeyscanner.run_statichoney()
        elif attack=="trivyscanner":
            honeyscanner.run_trivyscanner()
        elif attack=="dos":
            honeyscanner.run_dos()
        elif attack=="fuzz":
            honeyscanner.run_fuzzing()
        elif attack=="tarbomb":
            honeyscanner.run_tarbomb()
        elif attack=="all":
            honeyscanner.run_all_attacks()
        else:
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
