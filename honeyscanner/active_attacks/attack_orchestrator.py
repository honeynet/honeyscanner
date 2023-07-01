from math import floor
from .dos import DoS
from .fuzzing import Fuzzing
from .software_exploit import SoftwareExploit
from .tar_bomb import TarBomb
# from ssh_keep_aliver import SSHKeepAliver
# from .honeypot_port_scanner.honeypot_port_scanner import HoneypotPortScanner

class AttackOrchestrator:
    def __init__(self, honeypot):
        self.honeypot = honeypot
        self.attacks = [
            Fuzzing(honeypot), # Successfully ran! - not crashing the honeypot - try to get some insights instead of crashing
            TarBomb(honeypot), # should be rechecked, works but doesn't crash the honeypot
            SoftwareExploit(honeypot), # Successfully ran! - not managed to exploit something
            DoS(honeypot) # Successfully ran! - crashes the honeypot
            # SSHKeepAliver(honeypot) # Not working yet... I don't know if I should keep it
        ]
        self.results = []

    def run_HoneypotPortScanner(self):
        honeypot_scanner = HoneypotPortScanner(self.honeypot.get_ip())
        honeypot_scanner.run_scanner()

    def run_attacks(self):
        # First run the nmap scanner
        # self.run_HoneypotPortScanner()
        # Then run the attacks
        results = []
        for attack in self.attacks:
            result = attack.run_attack()
            results.append(result)
        self.results = results
    
    def generate_report(self, results):
        report = "Honeypot Attack Report\n"
        report += f"Target: {self.honeypot.get_ip()}:{self.honeypot.get_port()}\n\n"

        for idx, result in enumerate(results):
            attack = self.attacks[idx]
            attack_name = attack.__class__.__name__
            report += f"{attack_name}:\n"
            report += f"  Vulnerability found: {result[0]}\n"
            report += f"  Message: {result[1]}\n\n"
            report += f"  Time to execute: {floor(result[2])} seconds\n\n"
            if attack_name == "DoS":
                report += f"  Number of threads used: {result[3]}\n\n"
            elif attack_name == "Fuzzing":
                report += f"  Test cases executed: {result[3]}\n\n"
            elif attack_name == "SoftwareExploit":
                report += f"  Exploits used are saved in: {result[3]}\n\n"
            elif attack_name == "TarBomb":
                report += f"  Number of bombs used: {result[3]}\n\n"
            # elif attack_name == "SSHKeepAliver":
            #     report += f"  Number of keep-alive packets sent: {result[3]}\n\n"
        return report
