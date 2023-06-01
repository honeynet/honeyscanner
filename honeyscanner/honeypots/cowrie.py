import os
import json
from .base_honeypot import BaseHoneypot

class Cowrie(BaseHoneypot):
    def __init__(self, version, ip, port, username, password):
        super().__init__("cowrie", version, ip, port, username, password)
        self.vulnerabilities_file_mapping = self._create_vulnerabilities_file_mapping()
        self.vulnerabilities = self._load_vulnerabilities()

    @staticmethod
    def _create_vulnerabilities_file_mapping():
        versions = ["1.5.1", "1.5.3", "v2.1.0", "v2.4.0", "v2.5.0"]
        return {
            version: Cowrie._get_vulnerabilities_file_path(f"cowrie-{version}-vulnerabilities.json")
            for version in versions
        }

    @staticmethod
    def _get_vulnerabilities_file_path(filename):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(current_dir, '..', 'passive_attacks', 'vuln_analyzer', 'analysis_results', filename)

    def _load_vulnerabilities(self):
        file_path = self.vulnerabilities_file_mapping.get(self.get_version())
        if file_path is None:
            raise ValueError(f"Unsupported version: {self.get_version()}")

        with open(file_path, "r") as file:
            vulnerabilities = json.load(file)
        return vulnerabilities[self.get_version()]
    