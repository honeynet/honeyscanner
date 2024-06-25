import art

from honeypots import BaseHoneypot
from .container_security_scanner import ContainerSecurityScanner
from .static_analyzer import StaticAnalyzer
from typing import TypeAlias
from .vuln_analyzer import VulnerableLibrariesAnalyzer


class AttackOrchestrator:
    def __init__(self, honeypot: BaseHoneypot) -> None:
        """
        Initializes the AttackOrchestrator class for passive
        attacks on a Honeypot.

        Args:
            honeypot (BaseHoneypot): Specific Honeypot instance for
                                     use in the attack.
        """
        self.honeypot: BaseHoneypot = honeypot
        self.attacks: list[str] = [
            "VulnerableLibrariesAnalyzer",
            "StaticAnalyzer",
            "ContainerSecurityScanner"
        ]
        self.analyze_vulns_report: str = ""
        self.static_analysis_report: str = ""
        self.container_sec_report: str = ""
        self.recs: dict[str, str] = {"vuln": "", "static": "", "container": ""}

    def run_attacks(self) -> None:
        """
        Run VulnAnalyzer, StaticHoney, and TrivyScanner on the Honeypot.
        """
        Lookup: TypeAlias = dict[str, str]
        # Run VulnAnalyzer
        print(art.ascii_art_vulnanalyzer())
        analyzer = VulnerableLibrariesAnalyzer(self.honeypot.name,
                                               self.honeypot.owner)
        version: str = self.honeypot.version
        versions_list: list[dict] = self.honeypot.versions_list
        version_lookup: Lookup = {item["version"]: item["requirements_url"]
                                  for item in versions_list}
        self.analyze_vulns_report, self.recs["vuln"] = (
            analyzer.analyze_vulnerabilities(version,
                                             version_lookup.get(version))
        )
        print("Finished VulnAnalyzer!")

        # Run Static Analyzer
        print(art.ascii_art_statichoney())
        analyzer = StaticAnalyzer(self.honeypot.name,
                                  self.honeypot.source_code_url,
                                  self.honeypot.version)
        self.static_analysis_report, self.recs["static"] = analyzer.run()
        print("Finished StaticHoney!")

        # Run Trivy Scanner
        print(art.ascii_art_trivyscanner())
        owner: str = self.honeypot.owner
        # kippo doesn't have official Docker images, so I am using my own
        if self.honeypot.name == "kippo":
            owner = "aristofanischionis"
        scanner = ContainerSecurityScanner(owner, self.honeypot.name)
        self.container_sec_report, self.recs["container"] = scanner.scan_repository()
        print("Finished Trivy!")

        print("Finished all passive attacks successfully!")

    def generate_report(self) -> tuple[str, dict[str, str]]:
        """
        Formats strings to create a report of the passive attacks
        on the Honeypot.

        Returns:
            str: Generated report string.
        """
        report: str = "Honeypot Passive Attack Report\n"
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
        return (report, self.recs)
