import argparse
import re

from art import ascii_art_honeyscanner
from passive_attacks import HoneypotDetector
from error_handler import ErrorHandler

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
    # Added honeypot type argument with choices
    parser.add_argument(
        "--honeypot-type",
        type=str,
        choices=['cowrie', 'kippo', 'dionaea', 'conpot'],
        help="Type of honeypot to analyze"
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
    # Added timeout argument
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Scan timeout in seconds (default: 300)"
    )
    return parser.parse_args()


def main() -> None:
    """
    Main entry point of the program.
    """
    # Added error handler initialization
    error_handler = ErrorHandler()
    print(ascii_art_honeyscanner())

    try:
        args: argparse.Namespace = parse_arguments()
        detector = HoneypotDetector(args.target_ip)
        honeyscanner = detector.detect_honeypot(args.username, args.password, args.honeypot_type)
        
        if not honeyscanner:
            print(error_handler.handle_error('detection_failed', ip=args.target_ip))
            return
        
        try:
            # Updated to pass timeout argument
            honeyscanner.run_all_attacks(timeout=args.timeout)
        except TimeoutError:
            print(error_handler.handle_error('connection_timeout', ip=args.target_ip))
            return
        except Exception as e:
            print(error_handler.handle_error('scan_failed', ip=args.target_ip, error=str(e)))
            return
        
        try:
            honeyscanner.generate_evaluation_report()
        except Exception as e:
            print(error_handler.handle_error('report_failed', ip=args.target_ip, error=str(e)))
            return
        
    except ValueError as e:
        print(error_handler.handle_error('invalid_ip', ip=args.target_ip))
    except Exception as e:
        print(error_handler.handle_error('unexpected_error', error=str(e)))


if __name__ == "__main__":
    main()
