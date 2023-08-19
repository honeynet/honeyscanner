import os
import sys
import time
import threading
from nmap3 import Nmap
import json
from colorama import Fore, Style

def print_ascii_art_HonepotPortScanner():
    ascii_art = r"""
  ___ ___                                            __ __________              __   _________                                         
 /   |   \  ____   ____   ____ ___.__.______   _____/  |\______   \____________/  |_/   _____/ ____ _____    ____   ____   ___________ 
/    ~    \/  _ \ /    \_/ __ <   |  |\____ \ /  _ \   __\     ___/  _ \_  __ \   __\_____  \_/ ___\\__  \  /    \ /    \_/ __ \_  __ \
\    Y    (  <_> )   |  \  ___/\___  ||  |_> >  <_> )  | |    |  (  <_> )  | \/|  | /        \  \___ / __ \|   |  \   |  \  ___/|  | \/
 \___|_  / \____/|___|  /\___  > ____||   __/ \____/|__| |____|   \____/|__|   |__|/_______  /\___  >____  /___|  /___|  /\___  >__|   
       \/             \/     \/\/     |__|                                                 \/     \/     \/     \/     \/     \/       
    """
    print(ascii_art)

class HoneypotPortScanner:
    def __init__(self, ip_address):
        self.ip_address = ip_address
        self.report = {}
        self.output_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'analysis_results')
        self.scanning = True
        self.ports = []

    def scan_honeypot(self):
        nmap = Nmap()

        scan_result = nmap.nmap_version_detection(self.ip_address, args='-A -O -sC -T4')

        self.report['ip_address'] = self.ip_address

        host_info = scan_result[self.ip_address]

        if 'error' not in host_info:
            self.report['status'] = 'online'
            if 'hostnames' in host_info:
                self.report['hostnames'] = host_info['hostnames']
            else:
                self.report['hostnames'] = []

            if 'os' in host_info:
                self.report['os'] = host_info['os']
            else:
                self.report['os'] = []

            ports = {}
            for port_info in host_info['ports']:
                port = port_info['portid']
                ports[port] = {
                    'name': port_info['service']['name'] if 'name' in port_info['service'] else '',
                    'product': port_info['service']['product'] if 'product' in port_info['service'] else '',
                    'version': port_info['service']['version'] if 'version' in port_info['service'] else '',
                    'cpe': port_info['service']['cpe'] if 'cpe' in port_info['service'] else [],
                    'script': port_info['service']['script'] if 'script' in port_info['service'] else []
                }
            self.report['ports'] = ports
        else:
            self.report['status'] = 'offline'
        

    def save_report(self):
        if not os.path.exists(self.output_folder):
            os.makedirs(self.output_folder)
        filename = os.path.join(self.output_folder, 'report.json')
        with open(filename, 'w') as f:
            json.dump(self.report, f, indent=2)

    def print_summary(self):
        if self.report['status'] == 'online':
            print(Fore.GREEN + f"[+] IP Address {self.report['ip_address']} is online" + Style.RESET_ALL)
            print(Fore.YELLOW + "Hostnames:" + Style.RESET_ALL)
            for hostname in self.report['hostnames']:
                print("  -", hostname)

            print(Fore.YELLOW + "OS:" + Style.RESET_ALL)
            for os in self.report['os']:
                print("  -", os['osclass']['osfamily'], os['osclass']['osgen'])

            print(Fore.YELLOW + "Ports:" + Style.RESET_ALL)
            for port, data in self.report['ports'].items():
                print(f"  - Port {port}: {data['name']} ({data['product']} {data['version']})")
                self.ports = self.ports + [port]
        else:
            print(Fore.RED + f"[-] IP Address {self.report['ip_address']} is offline" + Style.RESET_ALL)

    def loading_animation(self):
        # chars = "/—\\|"
        chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        while self.scanning:
            for char in chars:
                sys.stdout.write(f"\rScanning with nmap in progress...{char}")
                sys.stdout.flush()
                time.sleep(0.1)
    
    def get_open_ports(self):
        return self.ports

    def run_scanner(self):
        print_ascii_art_HonepotPortScanner()
        loading_thread = threading.Thread(target=self.loading_animation, daemon=True)
        loading_thread.start()
        self.scan_honeypot()
        self.save_report()
        self.print_summary()
        self.scanning = False
        loading_thread.join(timeout=0.1)
        sys.stdout.write("\rFinished HoneypotPortScanner!      \n")
        sys.stdout.flush()
