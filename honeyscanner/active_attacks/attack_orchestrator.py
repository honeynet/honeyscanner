from math import floor
from .base_attack import AttackResults, BaseAttack, BaseHoneypot
from .dos import DoS
from .fuzzing import Fuzzing
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

    def generate_report(self) -> tuple[dict, int, int]:
        """
        Generates a report of the attack results.

        Returns:
            tuple[dict, int, int]: Dictionary report of attack results, total attacks, successful attacks
        """
        report = {
            "report_title": "Honeypot Active Attack Report",
            "target_ip": self.honeypot.ip,
            "attacks": [],
            "summary": {
                "total_attacks": self.total_attacks,
                "successful_attacks": self.successful_attacks,
                "success_rate": round((self.successful_attacks / self.total_attacks * 100), 2) if self.total_attacks > 0 else 0
            }
        }

        for idx, result in enumerate(self.results):
            attack = self.attacks[idx]
            attack_name = attack.__class__.__name__
            
            attack_data = {
                "attack_name": attack_name,
                "vulnerability_found": result[0],
                "message": result[1],
                "execution_time_seconds": int(result[2]),  # Using int instead of floor for cleaner code
                "additional_metrics": {}
            }
            
            # Add attack-specific metrics
            if attack_name == "DoS":
                attack_data["additional_metrics"]["threads_used"] = result[3]
            elif attack_name == "Fuzzing":
                attack_data["additional_metrics"]["test_cases_executed"] = result[3]
            elif attack_name == "TarBomb":
                attack_data["additional_metrics"]["bombs_used"] = result[3]
            elif attack_name == "DoSAllOpenPorts":
                attack_data["additional_metrics"]["threads_used"] = result[3]
            
            report["attacks"].append(attack_data)

        return (report, self.total_attacks, self.successful_attacks)