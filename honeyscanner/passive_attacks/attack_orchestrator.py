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

def execute_vuln_analyzer_code(honeypot):
    analyzer = VulnerableLibrariesAnalyzer(honeypot.name, honeypot.owner)
    version = honeypot.version
    versions_list = honeypot.versions_list
    version_lookup_dict = {item["version"]: item["requirements_url"] for item in versions_list}
    analyzer.analyze_vulnerabilities(version, version_lookup_dict.get(version))
        
def execute_static_analyzer_code(honeypot):
    analyzer = StaticAnalyzer(honeypot.name, honeypot.source_code_url, honeypot.version)
    analyzer.run()

def execute_trivy_scanner_code(honeypot):
    owner = honeypot.owner
    # kippo doesn't have official Docker images, so I am using my own
    if honeypot.name == "kippo":
        owner = "aristofanischionis"
    
    scanner = ContainerSecurityScanner(owner, honeypot.name)
    scanner.scan_repository()

class AttackOrchestrator:
    def __init__(self, honeypot):
        self.honeypot = honeypot
        self.results = []

    def run_attacks(self):
        # Run VulnAnalyzer
        print_ascii_art_VulnAnalyzer()
        execute_vuln_analyzer_code(self.honeypot)
        print("Finished VulnAnalyzer!")
        # Run Static Analyzer
        print_ascii_art_StaticHoney()
        execute_static_analyzer_code(self.honeypot)
        print("Finished StaticHoney!")
        # Run Trivy Scanner
        print_ascii_art_TrivyScanner()
        execute_trivy_scanner_code(self.honeypot)
        print("Finished Trivy!")
        print("Finished all analyzers!")
    
    def generate_report(self):
        # count how many potential cves are written in the all_cves.txt file and write this in the report
        # TODO:In the future improve this
        pass
