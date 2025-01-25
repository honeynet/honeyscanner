from math import floor
from .base_attack import AttackResults, BaseAttack, BaseHoneypot
from .dos import DoS
from .fuzzing import Fuzzing
from .tar_bomb import TarBomb
from error_handler import ErrorHandler

class AttackOrchestrator:
    def __init__(self, honeypot: BaseHoneypot) -> None:
        """
        Initializes an AttackOrchestrator object.

        Args:
            honeypot (BaseHoneypot): Honeypot object holding the information
                                     to use in the attacks.
        """
        # Added error handler initialization
        self.error_handler = ErrorHandler()

        self.honeypot = honeypot
        self.attacks: list[BaseAttack] = []

        try:
            if honeypot.name == "dionaea" or honeypot.name == "conpot":
                self.attacks = [
                    DoS(honeypot)
                ]
            else:
                self.attacks = [
                    Fuzzing(honeypot),
                    TarBomb(honeypot),
                    DoS(honeypot)
                ]
        except Exception as e:
            self.error_handler.handle_error('attack_initialization_failed', error=str(e))
            raise

        self.total_attacks: int = len(self.attacks)
        self.successful_attacks: int = 0
        self.results: AttackResults

    def run_attacks(self) -> None:
        """
        Runs all attacks that can be ran on the specified honeypot.
        """
        try:
            results = []
            for attack in self.attacks:
                try:
                    result = attack.run_attack()
                    if result[0]:
                        self.successful_attacks += 1
                    results.append(result)
                except Exception as e:
                    self.error_handler.handle_error('individual_attack_failed', 
                                                  attack=attack.__class__.__name__, 
                                                  error=str(e))
                    raise
            self.results = results
        except Exception as e:
            self.error_handler.handle_error('attack_execution_failed', error=str(e))
            raise

    def generate_report(self) -> tuple[str, int, int]:
        """
        Generates a report of the attack results.

        Returns:
            str: Report of the attack results to be saved for later.
        """
        try:
            report = "Honeypot Active Attack Report\n"
            report += "=============================\n\n"
            report += f"Target: {self.honeypot.ip}\n\n"
            
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
                elif attack_name == "TarBomb":
                    report += f"  Number of bombs used: {result[3]}\n\n"
                elif attack_name == "DoSAllOpenPorts":
                    report += f"  Number of threads used: {result[3]}\n\n"
            return (report, self.total_attacks, self.successful_attacks)
        except Exception as e:
            self.error_handler.handle_error('report_generation_failed', error=str(e))
            raise
