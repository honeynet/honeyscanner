import re
import time
import argparse
from core import Honeyscanner
from io import StringIO
from contextlib import redirect_stdout
import tkinter as tk
import sys

def print_ascii_art_honeyscanner():
    ascii_art = r"""

  ___ ___                                                                             
 /   |   \  ____   ____   ____ ___.__. ______ ____ _____    ____   ____   ___________ 
/    ~    \/  _ \ /    \_/ __ <   |  |/  ___// ___\\__  \  /    \ /    \_/ __ \_  __ \
\    Y    (  <_> )   |  \  ___/\___  |\___ \\  \___ / __ \|   |  \   |  \  ___/|  | \/
 \___|_  / \____/|___|  /\___  > ____/____  >\___  >____  /___|  /___|  /\___  >__|   
       \/             \/     \/\/         \/     \/     \/     \/     \/     \/       

        """
    print(ascii_art)

def sanitize_string(s):  
    s = s.strip()  
    s = s.lower()  
    # Remove special characters using regex (it matches any character that is not a lowercase letter, a number, a space, a dot, an underscore, or a hyphen and removes it.)  
    s = re.sub('[^a-z0-9._\- ]', '', s)  
    return s  

def parse_arguments():
    parser = argparse.ArgumentParser(description="Honeyscanner: A vulnerability analyzer for honeypots")
    parser.add_argument(
        "--honeypot",
        type=sanitize_string,
        required=True,
        choices=["cowrie", "kippo", "dionaea", "conpot","glastopf"],
        help="Honeypot to analyze, currently supported: (cowrie, kippo, dionaea and conpot)",
    )
    parser.add_argument(
        "--honeypot_version",
        type=sanitize_string,
        required=True,
        help="The version of the honeypot to analyze",
    )
    parser.add_argument(
        "--target_ip",
        type=sanitize_string,
        required=True,
        help="The IP address of the honeypot to analyze",
    )
    parser.add_argument(
        "--port",
        type=int,
        required=True,
        help="The port to connect to the honeypot to analyze",
    )
    parser.add_argument(
        "--username",
        type=str,
        required=False,
        help="The username to connect to the honeypot",
    )
    parser.add_argument(
        "--password",
        type=str,
        required=False,
        help="The password to connect to the honeypot",
    )
    return parser.parse_args()

def main():
    args = parse_arguments()
    print_ascii_art_honeyscanner()
    
    honeyscanner = Honeyscanner(args.honeypot, args.honeypot_version, args.target_ip, args.port, args.username, args.password)

    sleep_time = 5
    print(f"Starting in {sleep_time} seconds...")
    time.sleep(sleep_time)

    try:  
        honeyscanner.run_all_attacks()  
    except Exception as e:  
        print(f"An error occurred during the attacks: {e}")
        return

    try:
        honeyscanner.generate_evaluation_report()  
    except Exception as e:  
        print(f"An error occurred during report generation: {e}")
        return


def run_honeyscanner(honeypot_type, honeypot_version, honeypot_ip, honeypot_port, honeypot_username, honeypot_password, run_passive=True, run_active=True, terminal=None):
    sys.stdout = terminal
    sys.stderr = terminal
    print_ascii_art_honeyscanner()
    sleep_time = 5
    print(f"Starting in {sleep_time} seconds...")
    time.sleep(sleep_time)

    try:

        honeypot = Honeyscanner(honeypot_type, honeypot_version, honeypot_ip, honeypot_port, honeypot_username, honeypot_password)
        if run_passive:
            honeypot.run_all_passive_attacks()
        if run_active:
            honeypot.run_all_active_attacks()
        honeypot.generate_evaluation_report()
    except Exception as e:
        raise RuntimeError(f"An error occurred: {e}")
    finally:
        # Restore stdout and stderr to their default values
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__



if __name__ == "__main__":
    main()