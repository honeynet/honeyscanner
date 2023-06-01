import os
import sys
import json
import shutil
from urllib.request import urlretrieve
from zipfile import ZipFile
import subprocess
from colorama import Fore, init
sys.path.append(os.path.dirname(os.path.abspath(os.path.join(__file__, os.pardir))))
from .CVEAnalyzer import CVEAnalyzer

# requires bandit to be installed
# pip install bandit

class StaticAnalyzer:
    def __init__(self, honeypot_name, honeypot_url, honeypot_versions):
        init(autoreset=True)
        self.honeypot_name = honeypot_name
        self.honeypot_url = honeypot_url
        self.honeypot_versions = honeypot_versions
        self.output_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "analysis_results")

    def fetch_honeypot_version(self, version):
        """
        Fetch the specified honeypot version from GitHub and extract it to a folder.

        :param version: The version to fetch
        :return: The folder name where the honeypot was extracted
        """
        url = f"{self.honeypot_url}/{version}.zip"
        zip_filename = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"{self.honeypot_name}_{version}.zip")
        urlretrieve(url, zip_filename)

        with ZipFile(zip_filename, 'r') as zip_ref:
            zip_ref.extractall(os.path.dirname(os.path.abspath(__file__)))
        
        os.remove(zip_filename)
        # this may not work for other honeypots apart from cowrie
        if version.startswith("v"):
            version = version[1:]
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), f"{self.honeypot_name}-{version}")

    def analyze_honeypot_version(self, honeypot_folder, version):
        """
        Analyze the specified honeypot version using Bandit, filter the results,
        and save them to a JSON file.

        :param honeypot_folder: The folder where the honeypot is located
        :param version: The version of the honeypot
        """
        output_filename = f"{self.output_folder}/{self.honeypot_name}_{version}_analysis.json"

        # Run Bandit via subprocess
        cmd = f"bandit -r '{honeypot_folder}' -f json -o '{output_filename}'"

        with open(os.devnull, 'w') as devnull:
            process = subprocess.run(cmd, shell=True)
            # process = subprocess.run(cmd, shell=True, stdout=devnull, stderr=devnull)

        if process.returncode != 0 and process.stderr:
            print(f"Error running Bandit for {self.honeypot_name}_{version}:")
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
        :param version: The version of the honeypot
        """
        output_filename = f"{self.output_folder}/{self.honeypot_name}_{version}_analysis.json"
        with open(output_filename, "r") as file:
            data = json.load(file)

        summary = data[version]["summary"]
        high_count = summary["high_severity"]
        medium_count = summary["medium_severity"]

        print(f"{Fore.GREEN}Version: {version}")
        print(f"{Fore.RED}High Severity: {high_count}")
        print(f"{Fore.YELLOW}Medium Severity: {medium_count}\n")

    def run(self):
        """
        Run the static analysis for each honeypot version, save the results,
        and print the summary.
        """
        if not os.path.exists(self.output_folder):
            os.makedirs(self.output_folder)

        for version in self.honeypot_versions:
            print(f"Analyzing {self.honeypot_name} {version}")
            honeypot_folder = self.fetch_honeypot_version(version)
            output_filename = self.analyze_honeypot_version(honeypot_folder, version)
            print(f"Analysis complete for {self.honeypot_name} {version}")
            self.print_summary(version)
            # Run the CVEAnalyzer to check for CVEs
            analyzer = CVEAnalyzer(output_filename)
            analyzer.run()