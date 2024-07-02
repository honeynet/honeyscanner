import art
import json
import os
import sys
import time
import threading

from colorama import Fore, Style
from nmap3 import Nmap
from typing import TypeAlias

AttackPorts: TypeAlias = dict[str, dict[str, str]]
PortList: TypeAlias = list[int]
Report: TypeAlias = dict[str, str | list | dict[str, dict[str, dict[str, str | list]]]]


class HoneypotPortScanner:
    def __init__(self, ip_address: str):
        """
        Initializes a HoneypotPortScanner object.

        Args:
            ip_address (str): IP address of the Honeypot to scan.
        """
        self.ip_address = ip_address
        self.report: Report = {}
        curr_dir: str = os.path.dirname(os.path.abspath(__file__))
        self.output_folder: str = os.path.join(curr_dir, 'analysis_results')
        self.scanning: bool = True
        self.attack_ports: AttackPorts = {}
        self.ports: PortList = []

    def scan_honeypot(self):
        HostInfo: TypeAlias = dict[str, str | list[dict[str, str | dict]]]

        nmap = Nmap()
        scan_result: dict = nmap.nmap_version_detection(self.ip_address,
                                                        args='-A -O -sC -T4')
        self.report['ip_address'] = self.ip_address
        host_info: HostInfo = scan_result[self.ip_address]
        if 'error' not in host_info:
            self.report['status'] = 'online'
            if 'hostname' in host_info:
                self.report['hostnames'] = host_info['hostname']
            else:
                self.report['hostnames'] = []

            if 'osmatch' in host_info:
                self.report['os'] = host_info['osmatch']
            else:
                self.report['os'] = []

            report_ports: Report = {}
            attack_ports: AttackPorts = {}
            for port_info in host_info['ports']:
                port = port_info['portid']
                report_ports[port] = {
                    'name': port_info['service']['name'] if 'name' in port_info['service'] else '',
                    'product': port_info['service']['product'] if 'product' in port_info['service'] else '',
                    'version': port_info['service']['version'] if 'version' in port_info['service'] else '',
                    'cpe': port_info['service']['cpe'] if 'cpe' in port_info['service'] else [],
                    'script': port_info['service']['script'] if 'script' in port_info['service'] else []
                }
                attack_ports[port] = {
                    'name': port_info['service']['name'] if 'name' in port_info['service'] else ''
                }
            self.report['ports'] = report_ports
            self.attack_ports = attack_ports
        else:
            self.report['status'] = 'offline'

    def save_report(self) -> None:
        """
        Saves the scan results to a JSON file.
        """
        if not os.path.exists(self.output_folder):
            os.makedirs(self.output_folder)
        filename: str = os.path.join(self.output_folder, 'report.json')
        with open(filename, 'w') as f:
            json.dump(self.report, f, indent=2)

    def print_summary(self) -> None:
        """
        Outputs a summary of the scan results to the user.
        """
        if self.report['status'] == 'online':
            print(Fore.GREEN + f"\r[+] IP Address {self.report['ip_address']} is online" + Style.RESET_ALL)
            print(Fore.YELLOW + "Hostnames:" + Style.RESET_ALL)
            for hostname in self.report['hostnames']:
                print("  -", hostname['name'])

            print(Fore.YELLOW + "OS:" + Style.RESET_ALL)
            for opsys in self.report['os']:
                print("  -", opsys['osclass']['osfamily'], opsys['osclass']['osgen'])

            print(Fore.YELLOW + "Ports:" + Style.RESET_ALL)
            for port, data in self.report['ports'].items():
                print(f"  - Port {port}: {data['name']} ({data['product']} {data['version']})")
                self.ports = self.ports + [int(port)]
        else:
            print(Fore.RED + f"[-] IP Address {self.report['ip_address']} is offline" + Style.RESET_ALL)

    def loading_animation(self) -> None:
        """
        Loading animation for the scanner
        """
        chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        while self.scanning:
            for char in chars:
                sys.stdout.write(f"\rScanning with nmap in progress...{char}")
                sys.stdout.flush()
                time.sleep(0.1)

    def get_open_ports(self) -> PortList:
        # Replace with attack_ports and remove self.ports if not used anywhere
        return self.ports

    def run_scanner(self) -> None:
        print(art.ascii_art_port_scanner())
        loading_thread = threading.Thread(target=self.loading_animation,
                                          daemon=True)
        loading_thread.start()
        self.scan_honeypot()
        self.save_report()
        self.print_summary()
        self.scanning = False
        loading_thread.join(timeout=0.1)
        sys.stdout.write("\rFinished HoneypotPortScanner!      \n")
        sys.stdout.flush()
