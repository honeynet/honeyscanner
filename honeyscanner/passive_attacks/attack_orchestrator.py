# Ascii art I am using: https://patorjk.com/software/taag/

import sys
import time
import threading
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

def loading_animation():
    # chars = "/—\\|"
    chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    while True:
        for char in chars:
            sys.stdout.write(f"\rWorking on finding vulnerabilities...{char}")
            sys.stdout.flush()
            time.sleep(0.1)

def execute_vuln_analyzer_code(honeypot):
    analyzer = VulnerableLibrariesAnalyzer(honeypot.get_name(), honeypot.get_owner())
    versions_list = honeypot.get_versions_list()
    # TODO: hope this works
    analyzer.analyze_vulnerabilities(honeypot.get_version(), versions_list[honeypot.get_version()].get("requirements_url"))
    # analyzer.analyze_vulnerabilities(version["version"], version["requirements_url"])
        
def execute_static_analyzer_code(honeypot):
    analyzer = StaticAnalyzer(honeypot.get_name(), honeypot.get_source_code_url(), honeypot.get_version())
    analyzer.run()

def execute_trivy_scanner_code(honeypot):
    owner = honeypot.get_owner()
    # kippo doesn't have official Docker images, so I am using my own
    if honeypot.get_name() == "kippo":
        owner = "aristofanischionis"
    
    scanner = ContainerSecurityScanner(owner, honeypot.get_name())
    scanner.scan_repository()

class AttackOrchestrator:
    def __init__(self, honeypot):
        self.honeypot = honeypot
        self.results = []

    def run_attacks(self):
        print_ascii_art_VulnAnalyzer()
        loading_thread = threading.Thread(target=loading_animation, daemon=True)
        loading_thread.start()
        execute_vuln_analyzer_code(self.honeypot)
        loading_thread.join(timeout=0.1)
        sys.stdout.write("\rFinished VulnAnalyzer!      \n")
        sys.stdout.flush()
        # Run Static Analyzer
        print_ascii_art_StaticHoney()
        execute_static_analyzer_code(self.honeypot)
        sys.stdout.write("\rFinished StaticHoney!      \n")
        sys.stdout.flush()
        # Run Trivy Scanner
        print_ascii_art_TrivyScanner()
        execute_trivy_scanner_code(self.honeypot)
        sys.stdout.write("\rFinished Trivy!      \n")
        sys.stdout.write("\rFinished all analyzers!      \n")
        sys.stdout.flush()
    
    def generate_report(self):
        # count how many potential cves are written in the all_cves.txt file and write this in the report
        pass
