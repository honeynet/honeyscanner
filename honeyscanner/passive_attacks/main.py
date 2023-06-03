# Ascii art I am using: https://patorjk.com/software/taag/

import sys
import time
import threading
from vuln_analyzer.vuln_analyzer import VulnerableLibrariesAnalyzer
from static_analyzer.static_analyzer import StaticAnalyzer
from container_security_scanner.container_security_scanner import ContainerSecurityScanner

# to run: python3 main.py
  
versions_list = [
    {        
        "version": "1.5.1",        
        "requirements_url": "https://raw.githubusercontent.com/cowrie/cowrie/1.5.1/requirements.txt",
    },    
    {        
        "version": "1.5.3",        
        "requirements_url": "https://raw.githubusercontent.com/cowrie/cowrie/1.5.3/requirements.txt",    
    },    
    {        
        "version": "v2.1.0",        
        "requirements_url": "https://raw.githubusercontent.com/cowrie/cowrie/v2.1.0/requirements.txt",    
    },    
    {        
        "version": "v2.4.0",        
        "requirements_url": "https://raw.githubusercontent.com/cowrie/cowrie/v2.4.0/requirements.txt",    
    },    
    {        
        "version": "v2.5.0",        
        "requirements_url": "https://raw.githubusercontent.com/cowrie/cowrie/v2.5.0/requirements.txt",    
    }
]

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

def execute_vuln_analyzer_code():
    analyzer = VulnerableLibrariesAnalyzer(honeypot_name, owner, repo_name)
    for version in versions_list:
        analyzer.analyze_vulnerabilities(version["version"], version["requirements_url"])

def execute_static_analyzer_code():
    honeypot_url = "https://github.com/cowrie/cowrie/archive/refs/tags"
    honeypot_versions = ["1.5.1", "1.5.3", "v2.1.0", "v2.4.0", "v2.5.0"]
    analyzer = StaticAnalyzer(honeypot_name, honeypot_url, honeypot_versions)
    analyzer.run()

def execute_trivy_scanner_code():
    scanner = ContainerSecurityScanner(owner, honeypot_name)
    scanner.scan_repository()

def main_menu():
    print("Select an option:")
    print("1. Vulnerability Analyzer")
    print("2. Static Analyzer")
    print("3. Trivy Scanner")
    print("4. All Analyzers")
    print("5. Exit")

    choice = input("Enter the number of your choice: ")
    return choice

if __name__ == "__main__":
    honeypot_name = "cowrie"
    owner = "cowrie"
    repo_name = "cowrie"

    while True:
        choice = main_menu()
        if choice == "1":
            print_ascii_art_VulnAnalyzer()
            loading_thread = threading.Thread(target=loading_animation, daemon=True)
            loading_thread.start()
            execute_vuln_analyzer_code()
            loading_thread.join(timeout=0.1)
            sys.stdout.write("\rFinished VulnAnalyzer!      \n")
            sys.stdout.flush()
            break
        elif choice == "2":
            print_ascii_art_StaticHoney()
            execute_static_analyzer_code()
            sys.stdout.write("\rFinished StaticHoney!      \n")
            sys.stdout.flush()
            break
        elif choice == "3":
            print_ascii_art_TrivyScanner()
            execute_trivy_scanner_code()
            sys.stdout.write("\rFinished Trivy!      \n")
            sys.stdout.flush()
            break
        elif choice == "4":
            # Run all analyzers
            # Run Vulnerability Analyzer
            print_ascii_art_VulnAnalyzer()
            loading_thread = threading.Thread(target=loading_animation, daemon=True)
            loading_thread.start()
            execute_vuln_analyzer_code()
            loading_thread.join(timeout=0.1)
            sys.stdout.write("\rFinished VulnAnalyzer!      \n")
            sys.stdout.flush()
            # Run Static Analyzer
            print_ascii_art_StaticHoney()
            execute_static_analyzer_code()
            sys.stdout.write("\rFinished StaticHoney!      \n")
            sys.stdout.flush()
            # Run Trivy Scanner
            print_ascii_art_TrivyScanner()
            execute_trivy_scanner_code()
            sys.stdout.write("\rFinished Trivy!      \n")
            sys.stdout.write("\rFinished all analyzers!      \n")
            sys.stdout.flush()
            break
        elif choice == "5":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please enter a valid number.")
