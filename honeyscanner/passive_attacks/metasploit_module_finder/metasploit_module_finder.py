# This script finds the metasploit module for a given CVE.
import subprocess
import shutil
import logging
import os

logging.basicConfig(level=logging.INFO)

class Exploit:
    def __init__(self, cve, module):
        self.cve = cve
        self.module = module

class MetasploitModuleFinder:
    def __init__(self):
        self.exploits = []

    def is_msfconsole_installed(self):
        return shutil.which("/opt/metasploit-framework/bin/msfconsole") is not None

    def find_module(self, cve):
        command = f"/opt/metasploit-framework/bin/msfconsole -q -x 'search {cve}; exit'"
        try:
            output = subprocess.check_output(command, shell=True).decode()
            lines = output.split("\n")
            start_parsing = False  

            for line in lines:
                # This is the line just before the actual module lines
                if "----" in line:  
                    # Set the flag to start parsing the next lines
                    start_parsing = True  
                    # Skip the current line
                    continue  

                if start_parsing:
                    # Split the line into fields by multiple spaces
                    elements = line.split()  
                    
                    # If the line has less than 1 field, it's not a module line
                    if len(elements) < 1:  
                        break
                    
                    # The first element is always the index, the second element is the module name
                    module = elements[1]
                    self.exploits.append(Exploit(cve, module))
        except subprocess.CalledProcessError:
            logging.error(f"Failed to find module for CVE {cve}")

    def populate_exploits_from_file(self, file_path):
        if not os.path.exists(file_path):
            logging.error(f"The file {file_path} does not exist.")
            return None
        with open(file_path, "r") as file:
            cves = file.read().splitlines()
            for cve in cves:
                self.find_module(cve)

def run_exploit(module, target_ip, target_port):
    command = f"/opt/metasploit-framework/bin/msfconsole -q -x 'use {module}; set RHOSTS {target_ip}; set RPORT {target_port}; run; exit'"
    try:
        output = subprocess.check_output(command, shell=True).decode()
        logging.info(f"Exploit output: {output}")
    except subprocess.CalledProcessError:
        logging.error(f"Failed to run exploit {module} on {target_ip}:{target_port}")

def find_exploits():
    finder = MetasploitModuleFinder()
    if finder.is_msfconsole_installed():
        finder.populate_exploits_from_file("all_cves.txt")
        with open('metasploit_modules.txt', 'w') as f:
            for exploit in finder.exploits:
                f.write(f"{exploit.module}\n")
                logging.info(f"Found module {exploit.module} for {exploit.cve}")
                run_exploit(exploit.module, "127.0.0.1", "2222")  
    else:
        logging.error("msfconsole is not installed or not found in PATH.")

if __name__ == "__main__":
    find_exploits()
