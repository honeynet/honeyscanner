# Ascii art I am using: https://patorjk.com/software/taag/

from .vuln_analyzer import VulnerableLibrariesAnalyzer
from .static_analyzer import StaticAnalyzer
from .container_security_scanner import ContainerSecurityScanner

def print_ascii_art_VulnAnalyzer():
    ascii_art = r"""
____   ____      .__              _____                   .__                                 
\   \ /   /__ __ |  |    ____    /  _  \    ____  _____   |  |  ___.__.________  ____ _______ 
 \   Y   /|  |  \|  |   /    \  /  /_\  \  /    \ \__  \  |  | <   |  |\___   /_/ __ \\_  __ \
  \     / |  |  /|  |__|   |  \/    |    \|   |  \ / __ \_|  |__\___  | /    / \  ___/ |  | \/
   \___/  |____/ |____/|___|  /\____|__  /|___|  /(____  /|____// ____|/_____ \ \___  >|__|   
                            \/         \/      \/      \/       \/           \/     \/        

        """
    print(ascii_art)

def print_ascii_art_StaticHoney():
    ascii_art = r"""
  _________ __          __  .__         ___ ___                             
 /   _____//  |______ _/  |_|__| ____  /   |   \  ____   ____   ____ ___.__.
 \_____  \\   __\__  \\   __\  |/ ___\/    ~    \/  _ \ /    \_/ __ <   |  |
 /        \|  |  / __ \|  | |  \  \___\    Y    (  <_> )   |  \  ___/\___  |
/_______  /|__| (____  /__| |__|\___  >\___|_  / \____/|___|  /\___  > ____|
        \/           \/             \/       \/             \/     \/\/     
    """
    print(ascii_art)

def print_ascii_art_TrivyScanner():
    ascii_art = r"""
___________      .__               _________                                         
\__    ___/______|__|__  _____.__./   _____/ ____ _____    ____   ____   ___________ 
  |    |  \_  __ \  \  \/ <   |  |\_____  \_/ ___\\__  \  /    \ /    \_/ __ \_  __ \
  |    |   |  | \/  |\   / \___  |/        \  \___ / __ \|   |  \   |  \  ___/|  | \/
  |____|   |__|  |__| \_/  / ____/_______  /\___  >____  /___|  /___|  /\___  >__|   
                           \/            \/     \/     \/     \/     \/     \/       
    """
    print(ascii_art)

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
        print_ascii_art_VulnAnalyzer()
        analyzer = VulnerableLibrariesAnalyzer(self.honeypot.name, self.honeypot.owner)
        version = self.honeypot.version
        versions_list = self.honeypot.versions_list
        version_lookup_dict = {item["version"]: item["requirements_url"] for item in versions_list}
        self.analyze_vulns_report = analyzer.analyze_vulnerabilities(version, version_lookup_dict.get(version))
        print("Finished VulnAnalyzer!")
        # Run Static Analyzer
        print_ascii_art_StaticHoney()
        analyzer = StaticAnalyzer(self.honeypot.name, self.honeypot.source_code_url, self.honeypot.version)
        self.static_analysis_report = analyzer.run()
        print("Finished StaticHoney!")

        # Run Trivy Scanner
        print_ascii_art_TrivyScanner()
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
