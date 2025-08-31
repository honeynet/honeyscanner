import argparse
import re
import traceback
import json
import sys

from honeyscanner.art import ascii_art_honeyscanner
from honeyscanner.passive_attacks import HoneypotDetector


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


def run_honeyscanner(target_ip: str, username: str = "", password: str = "") -> dict:
    """
    Run honeyscanner programmatically with given parameters.
    
    Args:
        target_ip (str): The IP address of the honeypot to analyze
        username (str): The username to connect to the honeypot (optional)
        password (str): The password to connect to the honeypot (optional)
    
    Returns:
        dict: The evaluation report as a dictionary, or error information
    """
    target_ip = sanitize_string(target_ip)
    
    print(ascii_art_honeyscanner())
    detector = HoneypotDetector(target_ip)
    honeyscanner = detector.detect_honeypot(username, password)
    
    if not honeyscanner:
        return {"error": "Failed to detect honeypot", "target_ip": target_ip}

    try:
        honeyscanner.run_all_attacks()
    except Exception as e:
        issue: str = traceback.format_exc()
        print(f"An error occurred during the attacks: {issue}")
        return {"error": f"Attack execution failed: {e}", "target_ip": target_ip}

    try:
        report = honeyscanner.generate_evaluation_report()
        return report
    except Exception as e:
        issue: str = traceback.format_exc()
        print(f"An error occurred during report generation: {issue}")
        return {"error": f"Report generation failed: {e}", "target_ip": target_ip}


def main() -> None:
    """
    Main entry point of the program - maintains CLI compatibility.
    """
    args: argparse.Namespace = parse_arguments()
    
    result = run_honeyscanner(args.target_ip, args.username, args.password)
    
    # Print result as JSON for capture by subprocess
    print(json.dumps(result))
    
    # Exit with appropriate code
    if isinstance(result, dict) and "error" in result:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()