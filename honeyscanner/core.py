from honeypots import Cowrie, Kippo
from passive_attacks import AttackOrchestrator as PassiveAttackOrchestrator
from active_attacks import AttackOrchestrator as ActiveAttackOrchestrator
from report_generator import ReportGenerator

class Honeyscanner:
    def __init__(self, honeypot_type, honeypot_version, honeypot_ip, honeypot_port, honeypot_username, honeypot_password):
        self.honeypot = self.create_honeypot(honeypot_type, honeypot_version, honeypot_ip, honeypot_port, honeypot_username, honeypot_password)
        self.passive_attack_orchestrator = PassiveAttackOrchestrator(self.honeypot)
        self.active_attack_orchestrator = ActiveAttackOrchestrator(self.honeypot)
        self.passive_attack_results = None
        self.active_attack_results = None
        self.report_generator = ReportGenerator(self.honeypot)

    def create_honeypot(self, honeypot_type, honeypot_version, honeypot_ip, honeypot_port, honeypot_username, honeypot_password):  
        honeypot_class_map = {  
            'cowrie': Cowrie,  
            'kippo': Kippo,  
        }  
        if honeypot_type not in honeypot_class_map:  
            supported_honeypots = ', '.join(honeypot_class_map.keys())
            raise ValueError(f"Unsupported honeypot type: {honeypot_type}. Supported honeypots are: {supported_honeypots}")  
        return honeypot_class_map[honeypot_type](honeypot_version, honeypot_ip, honeypot_port, honeypot_username, honeypot_password)

    def run_all_attacks(self):
        # Passive attacks
        self.passive_attack_orchestrator.run_attacks()
        self.passive_attack_results = self.passive_attack_orchestrator.generate_report()
        # Active attacks
        self.active_attack_orchestrator.run_attacks()
        self.active_attack_results = self.active_attack_orchestrator.generate_report()

    def generate_evaluation_report(self):
        self.report_generator.generate_report(self.passive_attack_results, self.active_attack_results)
