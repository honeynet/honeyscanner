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
        # if version[0] == "v" and self.honeypot.name == "dionaea":
        #     version = version[1:]
        versions_list: list[dict] = self.honeypot.versions_list
        version_lookup: Lookup = {item["version"]: item["requirements_url"]
                                  for item in versions_list}
        result = analyzer.analyze_vulnerabilities(version, version_lookup.get(version))
        self.analyze_vulns_report = result["vulnerabilities"]
        self.recs["vuln"] = result["actions"]
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

    def generate_report(self) -> tuple[dict, dict[str, str]]:
        """
        Formats data to create a report of the passive attacks
        on the Honeypot.

        Returns:
            tuple[dict, dict[str, str]]: Dictionary report of attack results and recommendations.
        """
        report = {
            "report_title": "Honeypot Passive Attack Report",
            "target_ip": self.honeypot.ip,
            "attacks_performed": [],
            "attack_results": {}
        }

        for attack in self.attacks:
            report["attacks_performed"].append(attack)
            
            if attack == "VulnerableLibrariesAnalyzer":
                report["attack_results"]["VulnerableLibrariesAnalyzer"] = {
                    "attack_type": "Vulnerable Libraries Analysis",
                    "description": "Analysis of vulnerable libraries and dependencies",
                    "report_content": self.analyze_vulns_report,
                    "raw_report": self.analyze_vulns_report  # Keep raw for backward compatibility
                }
            elif attack == "StaticAnalyzer":
                report["attack_results"]["StaticAnalyzer"] = {
                    "attack_type": "Static Code Analysis",
                    "description": "Static analysis of honeypot codebase and configuration",
                    "report_content": self.static_analysis_report,
                    "raw_report": self.static_analysis_report  # Keep raw for backward compatibility
                }
            elif attack == "ContainerSecurityScanner":
                report["attack_results"]["ContainerSecurityScanner"] = {
                    "attack_type": "Container Security Scan",
                    "description": "Security analysis of container configuration and vulnerabilities",
                    "report_content": self.container_sec_report,
                    "raw_report": self.container_sec_report  # Keep raw for backward compatibility
                }

        # Add summary information
        report["summary"] = {
            "total_attacks_performed": len(self.attacks),
            "attack_types": list(set(self.attacks)),  # Unique attack types
            "recommendations_count": len(self.recs)
        }

        return (report, self.recs)