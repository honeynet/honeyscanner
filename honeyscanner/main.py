import os
import argparse
import json
from .core import honeyscanner
from passive_attacks.report_generation import generate_report
from passive_attacks.config import config

def print_ascii_art_honeyscanner():
    ascii_art = r"""

.__                                                                                
|  |__   ____   ____   ____ ___.__. ______ ____ _____    ____   ____   ___________ 
|  |  \ /  _ \ /    \_/ __ <   |  |/  ___// ___\\__  \  /    \ /    \_/ __ \_  __ \
|   Y  (  <_> )   |  \  ___/\___  |\___ \\  \___ / __ \|   |  \   |  \  ___/|  | \/
|___|  /\____/|___|  /\___  > ____/____  >\___  >____  /___|  /___|  /\___  >__|   
     \/            \/     \/\/         \/     \/     \/     \/     \/     \/       

        """
    print(ascii_art)


# Set the default report path to a file named "report.txt" in the "reports" folder
def set_default_report_path():
    backend_path = os.path.dirname(os.path.abspath(__file__))
    default_report_path = os.path.join(backend_path, "reports", "report.txt")
    return default_report_path


def parse_arguments():
    parser = argparse.ArgumentParser(description="honeyscanner: A vulnerability analyzer for honeypots")
    parser.add_argument(
        "--target_ip",
        type=str,
        required=True,
        help="The IP address of the honeypot to analyze",
    )
    parser.add_argument(
        "--honeypot",
        type=str,
        required=True,
        choices=["dionaea", "cowrie", "conpot"],
        help="Honeypot type to analyze (dionaea, cowrie, or conpot)",
    )
    parser.add_argument(
        "--honeypot_version",
        type=str,
        required=False,
        help="The version of the honeypot to analyze",
    )
    return parser.parse_args()


def main():
    args = parse_arguments()
    print_ascii_art_honeyscanner()
    honeyscanner = honeyscanner(args.target_ip, args.honeypot, args.honeypot_version)
    
    attack_results = honeyscanner.run_all_attacks()
    
    report_path = set_default_report_path()
    generate_report(attack_results, report_path)
    
    print(f"Report generated: {report_path}")


if __name__ == "__main__":
    main()
