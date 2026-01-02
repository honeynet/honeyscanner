from honeyscanner.active_attacks import AttackOrchestrator as ActiveAttackOrchestrator
from honeyscanner.honeypots import BaseHoneypot, Cowrie, Conpot, Dionaea, Kippo
from honeyscanner.passive_attacks import AttackOrchestrator as PassiveAttackOrchestrator
from honeyscanner.report_generator import ReportGenerator

from typing import Type, TypeAlias

HoneypotMap: TypeAlias = dict[str, Type[BaseHoneypot]]


class Honeyscanner:

    def __init__(self,
                 honeypot_type: str,
                 honeypot_version: str,
                 honeypot_ip: str,
                 honeypot_ports: set[int],
                 honeypot_username: str,
                 honeypot_password: str) -> None:
        """
        Initializes a new instance of a Honeyscanner object.

        Args:
            honeypot_type (str): Type of the Honeypot to analyze
            honeypot_version (str): Version of the Honeypot
            honeypot_ip (str): IP address of the Honeypot
            honeypot_ports (int): Open ports on the Honeypot
            honeypot_username (str): Username to authenticate with
            honeypot_password (str): Password to authenticate with
        """
        self.honeypot: BaseHoneypot = self.create_honeypot(honeypot_type,
                                                           honeypot_version,
                                                           honeypot_ip,
                                                           honeypot_ports,
                                                           honeypot_username,
                                                           honeypot_password)
        self.passive_attack_orchestrator: PassiveAttackOrchestrator = (
            PassiveAttackOrchestrator(self.honeypot)
        )
        self.active_attack_orchestrator: ActiveAttackOrchestrator = (
            ActiveAttackOrchestrator(self.honeypot)
        )
        self.recommendations: dict[str, str]
        self.passive_attack_results: str = ""
        self.active_attack_results: tuple[str, int, int]
        self.report_generator: ReportGenerator = ReportGenerator(self.honeypot)

    def create_honeypot(self,
                        honeypot_type: str,
                        honeypot_version: str,
                        honeypot_ip: str,
                        honeypot_ports: set[int],
                        honeypot_username: str,
                        honeypot_password: str) -> BaseHoneypot:
        """
        Creates a new Honeypot object based on the provided parameters.

        Args:
            honeypot_type (str): Type of Honeypot to analyze
            honeypot_version (str): Version of the Honeypot
            honeypot_ip (str): IP address of the Honeypot
            honeypot_ports (int): Open ports on the Honeypot
            honeypot_username (str): Username to authenticate with
            honeypot_password (str): Password to authenticate with

        Raises:
            ValueError: If the provided Honeypot type is not supported yet

        Returns:
            BaseHoneypot: An instance of the specified Honeypot to
            analyze data from
        """
        honeypot_class_map: HoneypotMap = {
            'cowrie': Cowrie,
            'kippo': Kippo,
            'dionaea': Dionaea,
            'conpot': Conpot
        }
        if honeypot_type not in honeypot_class_map:
            supported_honeypots: str = ', '.join(honeypot_class_map.keys())
            raise ValueError(f"Unsupported honeypot type: {honeypot_type}. \
                Supported honeypots are: {supported_honeypots}")
        return honeypot_class_map[honeypot_type](honeypot_version,
                                                 honeypot_ip,
                                                 honeypot_ports,
                                                 honeypot_username,
                                                 honeypot_password)

    def run_all_attacks(self) -> None:
        """
        Run all attacks on the Honeypot and save the attack findings.
        """
        # Passive attacks
        self.passive_attack_orchestrator.run_attacks()
        self.passive_attack_results, self.recommendations = (
            self.passive_attack_orchestrator.generate_report()
        )
        # Active attacks
        self.active_attack_orchestrator.run_attacks()
        self.active_attack_results: tuple[str, int, int] = (
            self.active_attack_orchestrator.generate_report()
        )

    def generate_evaluation_report(self) -> dict:
        """
        Generate the evaluation report for the Honeypot off of
        the attack results.
        """
        return self.report_generator.generate(list(self.recommendations.values()),
                                       self.passive_attack_results,
                                       self.active_attack_results)
