from math import floor

from .base_attack import AttackResults, BaseAttack, BaseHoneypot
from .dos import DoS
from .fuzzing import Fuzzing
# from .software_exploit import SoftwareExploit
from .tar_bomb import TarBomb


class AttackOrchestrator:
    def __init__(self, honeypot: BaseHoneypot) -> None:
        """
        Initializes an AttackOrchestrator object.

        Args:
            honeypot (BaseHoneypot): Honeypot object holding the information
                                     to use in the attacks.
        """
        self.honeypot = honeypot
        self.attacks: list[BaseAttack] = []
        if honeypot.name == "dionaea" or honeypot.name == "conpot":
            self.attacks = [
                DoS(honeypot)
            ]
        else:
            self.attacks = [
                Fuzzing(honeypot),
                TarBomb(honeypot),
                # TODO: SoftwareExploit still is slow
                # SoftwareExploit(honeypot),
                DoS(honeypot)
            ]
        self.total_attacks: int = len(self.attacks)
        self.successful_attacks: int = 0
        self.results: AttackResults

    def run_attacks(self) -> None:
        """
        Runs all attacks that can be ran on the specified honeypot.
        """
        # Then run the attacks
        results = []
        for attack in self.attacks:
            result = attack.run_attack()
            if result[0]:
                self.successful_attacks += 1
            results.append(result)
        self.results = results

    def generate_report(self) -> tuple[str, int, int]:
        """
        Generates a report of the attack results.

        Returns:
            str: Report of the attack results to be saved for later.
        """
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
        return (report, self.total_attacks, self.successful_attacks)
