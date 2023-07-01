import os
import sys
import json
import shutil
from urllib.request import urlretrieve
from zipfile import ZipFile
import subprocess
from pathlib import Path
from colorama import Fore, init
import requests
import re

# requires bandit to be installed
# pip install bandit

class StaticAnalyzer:
    def __init__(self, honeypot_name, honeypot_url, honeypot_version):
        init(autoreset=True)
        self.honeypot_name = honeypot_name
        self.honeypot_url = honeypot_url
        self.honeypot_version = honeypot_version
        self.output_folder = Path(__file__).resolve().parent / "analysis_results"
        self.all_cves_path = Path(__file__).resolve().parent.parent / "results" / "all_cves.txt"

    def fetch_honeypot_version(self, version):
        """
        Fetch the specified honeypot version from GitHub and extract it to a folder.
        """
        url = f"{self.honeypot_url}/{version}.zip"
        zip_filename = Path(__file__).resolve().parent / f"{self.honeypot_name}-{version}.zip"
        urlretrieve(url, zip_filename)

        with ZipFile(zip_filename, 'r') as zip_ref:
            zip_ref.extractall(Path(__file__).resolve().parent)
        
        os.remove(zip_filename)
        # this is cowrie specific
        if self.honeypot_name == "cowrie" and version.startswith("v"):
            version = version[1:]
        # this is kippo specific
        if self.honeypot_name == "kippo" and version.startswith("v"):
            version = version[1:]

        return Path(__file__).resolve().parent / f"{self.honeypot_name}-{version}"

    def analyze_honeypot_version(self, honeypot_folder, version):
        """
        Analyze the specified honeypot version using Bandit, filter the results,
        and save them to a JSON file.
        """
        output_filename = self.output_folder / f"{self.honeypot_name}_{version}_analysis.json"

        # Run Bandit via subprocess
        cmd = f"bandit -r '{honeypot_folder}' -f json -o '{output_filename}'"

        with open(os.devnull, 'w') as devnull:
            process = subprocess.run(cmd, shell=True)

        if process.returncode != 0 and process.stderr:
            print(f"Error running Bandit for {self.honeypot_name}-{version}:")
            print(process.stderr)

        # Read the JSON output file
        with open(output_filename, "r") as file:
            data = json.load(file)

        # Filter results based on severity
        filtered_results = [
            result for result in data["results"]
            if result["issue_severity"] in ["HIGH", "MEDIUM"]
        ]

        # Count the medium and high severity vulnerabilities
        high_count = sum(1 for result in filtered_results if result["issue_severity"] == "HIGH")
        medium_count = sum(1 for result in filtered_results if result["issue_severity"] == "MEDIUM")

        summary = {
            "high_severity": high_count,
            "medium_severity": medium_count
        }

        filtered_data = {
            version: {
                "summary": summary,
                "results": [
                    result for result in data["results"]
                    if result["issue_severity"] in ["HIGH", "MEDIUM"]
                ]
            }
        }

        # Write the modified JSON data back to the output file
        with open(output_filename, "w") as file:
            json.dump(filtered_data, file, indent=2)
        
        shutil.rmtree(honeypot_folder)
        return output_filename

    def print_summary(self, version):
        """
        Print the summary of the analysis results for the specified version using colored output.
        """
        output_filename = self.output_folder / f"{self.honeypot_name}_{version}_analysis.json"

        with open(output_filename, "r") as file:
            data = json.load(file)

        summary = data[version]["summary"]
        high_count = summary["high_severity"]
        medium_count = summary["medium_severity"]

        print(f"{Fore.GREEN}Version: {version}")
        print(f"{Fore.RED}High Severity: {high_count}")
        print(f"{Fore.YELLOW}Medium Severity: {medium_count}\n")

    @staticmethod
    def extract_cwe_links(output_filename):
        """
        Extract CWE links from the analysis results
        """
        cwe_links = []
        results = []

        print(Fore.GREEN + f"Extracting CWE links from {output_filename}...")
        with open(output_filename, 'r') as file:
            data = json.load(file)

        for key in data:
            results.extend(data[key].get('results', []))
        
        for result in results:
            cwe_link = result.get('issue_cwe', {}).get('link')
            if cwe_link:
                cwe_links.append(cwe_link)
        
        return cwe_links

    @staticmethod
    def scrape_cve_ids(cwe_links):
        """
        Scrape CVE IDs from CWE links
        """
        cve_ids = []

        print(Fore.GREEN + f"Scraping CVE IDs from CWE links...")
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}')
        for cwe_link in cwe_links:
            print(Fore.YELLOW + f"Scraping CVE IDs from {cwe_link}...")
            response = requests.get(cwe_link)
            if response.status_code == 200:
                cve_matches = cve_pattern.findall(response.text)
                for cve_id in cve_matches:
                    if cve_id not in cve_ids:
                        cve_ids.append(cve_id)
        
        return cve_ids

    def log_cves_to_file(self, cve_ids):
        """
        Append found CVEs to a file.
        """
        print(Fore.GREEN + f"Logging CVEs to file {self.all_cves_path}...")
        
        dir_path = self.all_cves_path.parent
        if not dir_path.exists():
            os.makedirs(dir_path)

        with open(self.all_cves_path, 'a') as file:
            for cve_id in cve_ids:
                file.write(f"{cve_id}\n")

    def run(self):
        """
        Run the static analysis for each honeypot version, save the results,
        and print the summary.
        """
        if not self.output_folder.exists():
            os.makedirs(self.output_folder)

        print(f"Analyzing {self.honeypot_name} {self.honeypot_version}")
        honeypot_folder = self.fetch_honeypot_version(self.honeypot_version)
        output_filename = self.analyze_honeypot_version(honeypot_folder, self.honeypot_version)
        print(f"Analysis complete for {self.honeypot_name} {self.honeypot_version}")
        self.print_summary(self.honeypot_version)
            
        cwe_links = self.extract_cwe_links(output_filename)
        cve_ids = self.scrape_cve_ids(cwe_links)
        self.log_cves_to_file(cve_ids)

        print(f"Found {len(cve_ids)} CVEs for {self.honeypot_name} {self.honeypot_version}")