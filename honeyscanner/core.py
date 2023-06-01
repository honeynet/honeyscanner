import json
from .honeypots import Dionaea, Cowrie, Conpot
from .active_attacks import DoS, Fuzzing, SoftwareExploit
from .passive_attacks.report_generation import generate_report

class honeyscanner:
    def __init__(self, honeypot_type, config_path):
        self.honeypot = self.create_honeypot(honeypot_type, config_path)
        self.attack_classes = [DoS, Fuzzing, SoftwareExploit]

    def create_honeypot(self, honeypot_type, config_path):
        honeypot_class_map = {
            'dionaea': Dionaea,
            'cowrie': Cowrie,
            'conpot': Conpot,
        }

        if honeypot_type not in honeypot_class_map:
            raise ValueError(f"Unsupported honeypot type: {honeypot_type}")

        config = self.load_configuration(config_path)
        return honeypot_class_map[honeypot_type](config)

    def load_configuration(self, config_path):
        with open(config_path, 'r') as config_file:
            config = json.load(config_file)
        return config

    def run_attacks(self):
        attack_results = []

        for AttackClass in self.attack_classes:
            attack = AttackClass(self.honeypot)
            success, message = attack.run_attack()
            attack_results.append({
                'attack_type': AttackClass.__name__,
                'success': success,
                'message': message,
            })

        return attack_results

    def generate_evaluation_report(self):
        attack_results = self.run_attacks()
        report_data = generate_report(self.honeypot.__class__.__name__, attack_results)
        return report_data
