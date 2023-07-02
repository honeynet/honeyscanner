import re
import time
import argparse
from core import Honeyscanner

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
    # Remove special characters using regex (it matches any character that is not a lowercase letter, a number, a space, or a dot and removes it.)
    s = re.sub('[^a-z0-9. ]', '', s)
    return s

def parse_arguments():
    parser = argparse.ArgumentParser(description="Honeyscanner: A vulnerability analyzer for honeypots")
    parser.add_argument(
        "--honeypot",
        type=sanitize_string,
        required=True,
        choices=["cowrie", "kippo"],
        help="Honeypot to analyze, currently supported: (cowrie and kippo)",
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
        honeyscanner.generate_evaluation_report()
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()

# Example run: python3 main.py --honeypot cowrie --honeypot_version 2.5.0 --target_ip 127.0.0.1 --port 2222 --username root --password 1234
# Example run: python3 main.py --honeypot kippo --honeypot_version 0.9 --target_ip 127.0.0.1 --port 2222 --username root --password 123456
# TODO: see again the software exploit module, SUPER SLOW maybe I can somehow speed it up
# TODO: tried kippo, change ssh connection to use: "ssh -p 2222 -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=ssh-dss,ssh-rsa root@127.0.0.1", it is needed, tarbomb can't connect
# TODO: fix the report