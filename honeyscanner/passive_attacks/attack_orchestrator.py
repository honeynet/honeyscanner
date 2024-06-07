import art

from .vuln_analyzer import VulnerableLibrariesAnalyzer
from .static_analyzer import StaticAnalyzer
from .container_security_scanner import ContainerSecurityScanner


class AttackOrchestrator:
    def __init__(self, honeypot):
        self.honeypot = honeypot
        self.attacks = [
            "VulnerableLibrariesAnalyzer",
            "StaticAnalyzer",
            "ContainerSecurityScanner"
        ]
        self.analyze_vulns_report = ""
        self.static_analysis_report = ""
        self.container_sec_report = ""

    def run_attacks(self):
        # Run VulnAnalyzer
        print(art.ascii_art_vulnanalyzer())
        analyzer = VulnerableLibrariesAnalyzer(self.honeypot.name,
                                               self.honeypot.owner)
        version = self.honeypot.version
        versions_list = self.honeypot.versions_list
        version_lookup_dict = {item["version"]: item["requirements_url"]
                               for item in versions_list}
        self.analyze_vulns_report = analyzer.analyze_vulnerabilities(version,
                                                                     version_lookup_dict.get(version))
        print("Finished VulnAnalyzer!")

        # Run Static Analyzer
        print(art.ascii_art_statichoney())
        analyzer = StaticAnalyzer(self.honeypot.name,
                                  self.honeypot.source_code_url,
                                  self.honeypot.version)
        self.static_analysis_report = analyzer.run()
        print("Finished StaticHoney!")

        # Run Trivy Scanner
        print(art.ascii_art_trivyscanner())
        owner = self.honeypot.owner
        # kippo doesn't have official Docker images, so I am using my own
        if self.honeypot.name == "kippo":
            owner = "aristofanischionis"
        scanner = ContainerSecurityScanner(owner, self.honeypot.name)
        self.container_sec_report = scanner.scan_repository()
        print("Finished Trivy!")

        print("Finished all passive attacks successfully!")

    def generate_report(self):
        report = "Honeypot Passive Attack Report\n"
        report += "==============================\n\n"
        report += f"Target: {self.honeypot.ip}:{self.honeypot.port}\n\n"

        for attack in self.attacks:
            report += f"{attack}:\n"
            if attack == "VulnerableLibrariesAnalyzer":
                report += self.analyze_vulns_report
                report += "\n\n"
            elif attack == "StaticAnalyzer":
                report += self.static_analysis_report
                report += "\n\n"
            elif attack == "ContainerSecurityScanner":
                report += self.container_sec_report
                report += "\n\n"
        return report
