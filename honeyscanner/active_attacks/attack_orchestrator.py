from math import floor
from .dos import DoS
from .fuzzing import Fuzzing
from .software_exploit import SoftwareExploit
from .tar_bomb import TarBomb
from .dos_all_open_ports import DoSAllOpenPorts

class AttackOrchestrator:
    def __init__(self, honeypot):
        self.honeypot = honeypot
        # for dionaea and conpot, we can run the DoSAllOpenPorts attack only
        self.attacks = []
        if honeypot.name == "dionaea":
            self.attacks = [
                DoSAllOpenPorts(honeypot)
            ]
        else:
            self.attacks = [
                Fuzzing(honeypot), # Successfully ran! - not crashing the honeypot - try to get some insights instead of crashing
                TarBomb(honeypot), # should be rechecked, works but doesn't crash the honeypot
                # TODO: SoftwareExploit still is slow
                #SoftwareExploit(honeypot), # Successfully ran! - not managed to exploit something
                DoS(honeypot) # Successfully ran! - crashes the honeypot
            ]
        self.results = []

    def run_attacks(self):
        # Then run the attacks
        results = []
        for attack in self.attacks:
            result = attack.run_attack()
            results.append(result)
        self.results = results
    
    def generate_report(self):
        report = "Honeypot Active Attack Report\n"
        report += "=============================\n\n"
        report += f"Target: {self.honeypot.ip}:{self.honeypot.port}\n\n"

        for idx, result in enumerate(self.results):
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
            elif attack_name == "DoSAllOpenPorts":
                report += f"  Number of threads used: {result[3]}\n\n"
        return report
