import json
import os
import re
import requests
import shutil
import subprocess
import tempfile

from colorama import Fore, init
from pathlib import Path
from typing import TypeAlias
from urllib.request import urlretrieve
from zipfile import ZipFile

FilteredRes: TypeAlias = list[dict[str, str]]
FilteredJSON: TypeAlias = dict[str, dict[str, FilteredRes]]

# requires bandit to be installed
# pip install bandit


class StaticAnalyzer:
    def __init__(self,
                 honeypot_name: str,
                 honeypot_url: str,
                 honeypot_version: str) -> None:
        init(autoreset=True)
        self.honeypot_name = honeypot_name
        self.honeypot_url = honeypot_url
        self.honeypot_version = honeypot_version
        # Check for Conpot's condition
        if honeypot_name == "conpot" and honeypot_version > "0.2.2":
            self.honeypot_version = f"Release_{honeypot_version}"
        # self.parent_path: Path = Path(__file__).resolve().parent
        # self.output_folder: Path = self.parent_path / "analysis_results"
        # passive_root: Path = self.parent_path.parent
        # self.all_cves_path: Path = passive_root / "results" / "all_cves.txt"
        # self.recommendation: str = ""

        base_temp = Path(tempfile.gettempdir())
        self.parent_path: Path = base_temp / "honeyscanner"
        self.output_folder: Path = self.parent_path / "static_analyzer" / "analysis_results"
        passive_root: Path = self.parent_path  # Changed to stay within temp dir
        self.all_cves_path: Path = passive_root / "results" / "all_cves.txt"
        self.recommendation: str = ""

        # Ensure directories exist
        self.output_folder.mkdir(parents=True, exist_ok=True)
        self.all_cves_path.parent.mkdir(parents=True, exist_ok=True)


    def fetch_honeypot_version(self, version: str) -> Path:
        """
        Fetch the specified honeypot version from GitHub and
        extract it to a folder.

        Args:
            version (str): Version of the honeypot to fetch.

        Returns:
            Path: BytesPath object
        """

        url: str = f"{self.honeypot_url}/{version}.zip"
        zip_filename: Path = self.parent_path / "static_analyzer" / f"{self.honeypot_name}-{version}.zip"
        urlretrieve(url, zip_filename)

        with ZipFile(zip_filename, 'r') as zip_ref:
            zip_ref.extractall(self.parent_path / "static_analyzer")

        os.remove(zip_filename)
        # this is cowrie specific
        if self.honeypot_name == "cowrie" and version.startswith("v"):
            version = version[1:]
        # this is kippo specific
        if self.honeypot_name == "kippo" and version.startswith("v"):
            version = version[1:]

        return self.parent_path / "static_analyzer" / f"{self.honeypot_name}-{version}"

    def analyze_honeypot_version(self,
                                 honeypot_folder: Path,
                                 version: str) -> Path:
        """
        Analyze the specified honeypot version using Bandit, filter
        the results, and save them to a JSON file.

        Args:
            honeypot_folder (Path): Path to the folder containing the
                                    honeypot code.
            version (str): Version of the honeypot to analyze.

        Returns:
            Path: Path to the JSON file containing the analysis results.
        """
        CompletedProc: TypeAlias = subprocess.CompletedProcess

        output_filename: Path = self.output_folder / f"{self.honeypot_name}_{version}_analysis.json"

        # Run Bandit via subprocess
        cmd: str = f"bandit -r '{honeypot_folder}' -f json -o '{output_filename}'"

        with open(os.devnull, 'w'):
            process: CompletedProc = subprocess.run(cmd, shell=True)

        if process.returncode != 0 and process.stderr:
            print(f"Error running Bandit for {self.honeypot_name}-{version}:")
            print(process.stderr)

        # Read the JSON output file
        with open(output_filename, "r") as file:
            data: dict = json.load(file)

        # Filter results based on severity
        filtered_results: FilteredRes = [
            result for result in data["results"]
            if result["issue_severity"] in ["HIGH", "MEDIUM"]
        ]

        # Count the medium and high severity vulnerabilities
        high_count: int = sum(1
                              for result in filtered_results
                              if result["issue_severity"] == "HIGH")
        medium_count: int = sum(1
                                for result in filtered_results
                                if result["issue_severity"] == "MEDIUM")

        if high_count > 0 or medium_count > 0:
            self.actionable_rec = "Bandit found vulnerabilities that can be exploited. Please refer to the StaticHoney's output for more details."

        summary: dict[str, int] = {
            "high_severity": high_count,
            "medium_severity": medium_count
        }

        filtered_data: FilteredJSON = {
            version: {
                "summary": summary,
                "results": filtered_results
            }
        }

        # Write the modified JSON data back to the output file
        with open(output_filename, "w") as file:
            json.dump(filtered_data, file, indent=2)

        shutil.rmtree(honeypot_folder)
        return output_filename

    def print_summary(self, version: str) -> None:
        """
        Print the summary of the analysis results for the specified
        version using colored output.

        Args:
            version (str): Version of the honeypot to get analysis
                           results from.
        """
        output_filename: Path = self.output_folder / f"{self.honeypot_name}_{version}_analysis.json"

        with open(output_filename, "r") as file:
            data: FilteredJSON = json.load(file)

        summary: dict[str, int] = data[version]["summary"]
        high_count: int = summary["high_severity"]
        medium_count: int = summary["medium_severity"]

        # print(f"{Fore.GREEN}Version: {version}")
        print(f"{Fore.RED}High Severity: {high_count}")
        print(f"{Fore.YELLOW}Medium Severity: {medium_count}\n")

    @staticmethod
    def extract_cwe_links(output_filename: Path) -> list[str]:
        """
        Extract CWE links from the analysis results
        """
        cwe_links: list[str] = []
        results: FilteredRes = []

        print(Fore.GREEN + f"Extracting CWE links from {output_filename}...")
        with open(output_filename, 'r') as file:
            data: FilteredJSON = json.load(file)

        for key in data:
            results.extend(data[key].get('results', []))

        for result in results:
            cwe_link: str = result.get('issue_cwe', {}).get('link')
            if cwe_link:
                cwe_links.append(cwe_link)

        return cwe_links

    @staticmethod
    def scrape_cve_ids(cwe_links: list[str]) -> set[str]:
        """
        Scrape CVE IDs from CWE links

        Args:
            cwe_links (list[str]): List of CWE links

        Returns:
            list[str]: CVE IDs
        """
        cve_ids: set[str] = set()

        print(Fore.GREEN + "Scraping CVE IDs from CWE links...")
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}')
        for cwe_link in cwe_links:
            print(Fore.YELLOW + f"Scraping CVE IDs from {cwe_link}...")
            response = requests.get(cwe_link)
            if response.status_code == 200:
                cve_matches: list[str] = cve_pattern.findall(response.text)
                for cve_id in cve_matches:
                    if cve_id not in cve_ids:
                        cve_ids.add(cve_id)

        return cve_ids

    def log_cves_to_file(self, cve_ids: set[str]) -> None:
        """
        Append found CVEs to a log file.

        Args:
            cve_ids (list[str]): List of CVE IDs
        """
        print(Fore.GREEN + f"Logging CVEs to file {self.all_cves_path}...")
        dir_path: Path = self.all_cves_path.parent
        if not dir_path.exists():
            os.makedirs(dir_path)

        with open(self.all_cves_path, 'a') as file:
            for cve_id in cve_ids:
                file.write(f"{cve_id}\n")

    def run(self) -> tuple[str, str]:
        """
        Run the static analysis for each honeypot version, save the results,
        and print the summary.

        Returns:
            str: Summary of the analysis results.
        """
        if not self.output_folder.exists():
            os.makedirs(self.output_folder)
        print(f"Analyzing {self.honeypot_name} {self.honeypot_version}")
        honeypot_folder: Path = self.fetch_honeypot_version(self.honeypot_version)
        output_filename: Path = self.analyze_honeypot_version(honeypot_folder,
                                                              self.honeypot_version)
        print(f"Analysis complete for {self.honeypot_name} {self.honeypot_version}")
        self.print_summary(self.honeypot_version)

        cwe_links: list[str] = self.extract_cwe_links(output_filename)
        cve_ids: set[str] = self.scrape_cve_ids(cwe_links)
        self.log_cves_to_file(cve_ids)

        print(f"Found {len(cve_ids)} CVEs for {self.honeypot_name} {self.honeypot_version}")

        return self.generate_summary(self.honeypot_version)

    def generate_summary(self, version: str) -> dict:
        """
        Generate the summary of the analysis results for the specified version
        as a dictionary.

        Args:
            version (str): The version of the honeypot to generate
                           the summary for.

        Returns:
            dict: A dictionary containing the summary of the analysis results
                  and actionable recommendations.
        """
        output_filename: Path = self.output_folder / f"{self.honeypot_name}_{version}_analysis.json"

        with open(output_filename, "r") as file:
            data: FilteredJSON = json.load(file)

        summary: dict[str, int] = data[version]["summary"]
        results: list[dict] = data[version]["results"]
        high_count: int = summary["high_severity"]
        medium_count: int = summary["medium_severity"]
        medium_issues: list[dict] = []
        high_issues: list[dict] = []

        for result in results:
            severity: str = result.get("issue_severity", [])
            issue_details = {
                "filename": result['filename'].split('static_analyzer/')[1],
                "line_number": result['line_number'],
                "issue_text": result['issue_text']
            }
            if severity == "HIGH":
                high_issues.append(issue_details)
            elif severity == "MEDIUM":
                medium_issues.append(issue_details)

        return {
            "version": version,
            "high_severity_count": high_count,
            "medium_severity_count": medium_count,
            "high_severity_issues": high_issues,
            "medium_severity_issues": medium_issues,
            "actionable_recommendation": self.actionable_rec
        }
