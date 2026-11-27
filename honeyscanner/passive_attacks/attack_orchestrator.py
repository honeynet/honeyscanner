import honeyscanner.art as art
from honeyscanner.progress import progress_manager

from honeyscanner.honeypots import BaseHoneypot
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
        progress_manager.log(art.ascii_art_vulnanalyzer())
        with progress_manager.spinner(f"Analyzing {self.honeypot.name} dependency vulnerabilities (Safety DB)..."):
            analyzer = VulnerableLibrariesAnalyzer(self.honeypot.name,
                                                   self.honeypot.owner)
            version: str = self.honeypot.version
            # if version[0] == "v" and self.honeypot.name == "dionaea":
            #     version = version[1:]
            versions_list: list[dict] = self.honeypot.versions_list
            version_lookup: Lookup = {item["version"]: item["requirements_url"]
                                      for item in versions_list}
            result = analyzer.analyze_vulnerabilities(version, version_lookup.get(version))
            self.analyze_vulns_report = result["vulnerability_analysis"]
            self.recs["vuln"] = result["vulnerability_analysis"]["action_required"]
        progress_manager.log("Finished VulnAnalyzer!")
        progress_manager.advance_overall(description="Static Code Analysis")

        # Run Static Analyzer
        progress_manager.log(art.ascii_art_statichoney())
        with progress_manager.spinner(f"Running Bandit static code analysis on {self.honeypot.name} {self.honeypot.version}..."):
            analyzer = StaticAnalyzer(self.honeypot.name,
                                      self.honeypot.source_code_url,
                                      self.honeypot.version)
            result = analyzer.run()
            self.static_analysis_report = result
            self.recs["static"] = result["actionable_recommendation"] 
        progress_manager.log("Finished StaticHoney!")
        progress_manager.advance_overall(description="Container Security Scan")

        # Run Trivy Scanner
        progress_manager.log(art.ascii_art_trivyscanner())
        owner: str = self.honeypot.owner
        # kippo doesn't have official Docker images, so I am using my own
        if self.honeypot.name == "kippo":
            owner = "aristofanischionis"
        with progress_manager.spinner(f"Running Trivy container scan on {owner}/{self.honeypot.name}..."):
            scanner = ContainerSecurityScanner(owner, self.honeypot.name)
            result, self.recs["container"] = scanner.scan_repository()
            self.container_sec_report = result
            self.container_sec_report["actionable_recommendation"] = self.recs["container"]
        progress_manager.log("Finished Trivy!")

        progress_manager.log("Finished all passive attacks successfully!")
        progress_manager.advance_overall(description="Passive Attacks Complete")

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
                }
            elif attack == "StaticAnalyzer":
                report["attack_results"]["StaticAnalyzer"] = {
                    "attack_type": "Static Code Analysis",
                    "description": "Static analysis of honeypot codebase and configuration",
                    "report_content": self.static_analysis_report,
                }
            elif attack == "ContainerSecurityScanner":
                report["attack_results"]["ContainerSecurityScanner"] = {
                    "attack_type": "Container Security Scan",
                    "description": "Security analysis of container configuration and vulnerabilities",
                    "report_content": self.container_sec_report,
                }

        # Add summary information
        report["summary"] = {
            "total_attacks_performed": len(self.attacks),
            "attack_types": list(set(self.attacks)),  # Unique attack types
            "recommendations_count": len(self.recs)
        }

        return (report, self.recs)