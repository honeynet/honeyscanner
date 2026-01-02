import json
import logging
import pkg_resources
import os
import requests
import time
import tempfile

from .models import Vulnerability
from collections import defaultdict
from colorama import Fore, Style, init
from datetime import datetime
from github import Github, GitRelease, NamedUser, Repository
from packaging.version import parse as pkg_version_parse
from packaging.specifiers import SpecifierSet
from pathlib import Path
from typing import TypeAlias

ReqList: TypeAlias = list[pkg_resources.Requirement]
UpdReqs: TypeAlias = list[str]
VulnLibs: TypeAlias = dict[str, list[Vulnerability]]


class VulnerableLibrariesAnalyzer:
    def __init__(self, honeypot_name: str, owner: str) -> None:
        logging.basicConfig(level=logging.INFO, format="%(message)s")
        init(autoreset=True)
        self.honeypot_name: str = honeypot_name
        self.owner: str = owner
        self.repo: Repository = self.get_repo()
        # parent_path: Path = Path(__file__).resolve().parent
        # self.insecure_full_path: Path = (
        #     parent_path / "vuln_database" / "insecure_full.json"
        # )
        # self.analysis_results_path: Path = parent_path / "analysis_results"
        # self.requirements_files_path: Path = parent_path / "requirements_files"
        # self.all_cves_path: Path = (
        #     parent_path.parent / "results" / "all_cves.txt"
        # )

        base_temp = Path(tempfile.gettempdir())
        parent_path: Path = base_temp / "honeyscanner"
        self.insecure_full_path: Path = parent_path / "vuln_database" / "insecure_full.json"
        self.analysis_results_path: Path = parent_path / "vuln_analyzer" / "analysis_results"
        self.requirements_files_path: Path = parent_path / "requirements_files"
        self.all_cves_path: Path = parent_path / "results" / "all_cves.txt"

        # Ensure directories exist
        self.insecure_full_path.parent.mkdir(parents=True, exist_ok=True)
        self.analysis_results_path.mkdir(parents=True, exist_ok=True)
        self.requirements_files_path.mkdir(parents=True, exist_ok=True)
        self.all_cves_path.parent.mkdir(parents=True, exist_ok=True)


        self.download_insecure_full_json()
        self.vuln_data_cache = defaultdict(dict)

    def get_repo(self) -> Repository:
        """
        Get the repository object to interact with.

        Returns:
            Repository: The repository interaction object for the
                        specified honeypot.
        """
        git: Github = Github()
        user: NamedUser = git.get_user(self.owner)
        return user.get_repo(self.honeypot_name)

    def download_insecure_full_json(self) -> None:
        """
        Download the insecure_full.json file containing vulnerability data.
        """
        url: str = "https://raw.githubusercontent.com/pyupio/safety-db/master/data/insecure_full.json"
        response: requests.Response = requests.get(url)
        if response.status_code == 200:
            if not self.insecure_full_path.parent.is_dir():
                self.insecure_full_path.parent.mkdir()

            with open(self.insecure_full_path, "w") as f:
                f.write(response.text)
        else:
            logging.error("\nFailed to download the insecure_full.json file\n")
            exit(1)

    def get_release_ver(self,
                        package_name: str,
                        date: datetime.date) -> str:
        """
        Get the latest version of the package released before
        the specified date.

        Args:
            package_name (str): The name of the package.
            date (datetime.date): The date to compare against.

        Returns:
            str: The latest version of the package released before the
                 specified date.
        """
        url: str = f"https://pypi.org/pypi/{package_name}/json"
        response: requests.Response = requests.get(url)
        if response.status_code == 200:
            releases: dict = response.json()["releases"]
            latest_version: str = ""
            for release_version in releases:
                try:
                    if (not releases[release_version]
                            or "upload_time" not in releases[release_version][0]):
                        continue
                    release_date_str: str = releases[release_version][0]["upload_time"]
                    release_date_obj: datetime = datetime.strptime(
                        release_date_str,
                        "%Y-%m-%dT%H:%M:%S")
                    if release_date_obj.date() <= date:
                        if (not latest_version
                                or pkg_version_parse(release_version)
                                > pkg_version_parse(latest_version)):
                            latest_version = release_version
                except Exception as e:
                    print(f"Error processing {package_name} version {release_version}: {e}")
            return latest_version
        return ""

    def update_versions(self,
                        requirements: ReqList,
                        release_date: datetime.date) -> UpdReqs:
        """
        Update the versions in the requirements list to the latest
        version before the release date.

        Args:
            requirements (ReqList): List of module requirements objects.
            release_date (datetime.date): Date of the release.

        Returns:
            UpdReqs: List of updated module requirements in string format.
        """
        Spec: TypeAlias = tuple[str, str]
        spec_ops: set[str, str] = {">=", "<="}

        updated_requirements: UpdReqs = []
        for req in requirements:
            spec: Spec = req.specs[0] if req.specs else None
            if spec:
                operator: str = spec[0]
                version: str = spec[1]
                if operator in spec_ops:
                    latest_version: str = self.get_release_ver(req.name,
                                                               release_date)
                    if latest_version:
                        updated_requirements.append(
                            f"{req.name}=={latest_version}"
                        )
                    else:
                        updated_requirements.append(f"{req.name}=={version}")
                else:
                    updated_requirements.append(str(req))
            else:
                latest_version: str = self.get_release_ver(req.name,
                                                           release_date)
                if latest_version:
                    updated_requirements.append(f"{req.name}=={latest_version}")
                else:
                    updated_requirements.append(str(req))
        return updated_requirements

    def download_requirements(self,
                              version: str,
                              requirements_url: str) -> bool:
        """
        Download the requirements.txt file and update the versions to
        the latest version before the release date.

        Args:
            version (str): The version of the package to download.
            requirements_url (str): The URL of the requirements.txt file.

        Returns:
            bool: True if the requirements were downloaded successfully,
                  False otherwise.
        """
        if not requirements_url:
            return False
        release_date: datetime.date = self.get_release_date(version)
        response: requests.Response = requests.get(requirements_url)
        if response.status_code == 200:
            requirements: ReqList = list(pkg_resources.parse_requirements(response.text))
            updated_requirements: UpdReqs = self.update_versions(requirements,
                                                                 release_date)
            if not self.requirements_files_path.is_dir():
                self.requirements_files_path.mkdir()
            reqs_path: str = f"{self.requirements_files_path}/{self.honeypot_name}-{version}-requirements.txt"
            with open(reqs_path, "w") as file:
                file.write("\n".join(updated_requirements))
            return True
        return False

    def get_release_date(self, version_tag: str) -> datetime.date:
        """
        Get the release date of the specified version tag.

        Args:
            version_tag (str): The version tag to get the release date for.

        Returns:
            datetime.date: The release date of the specified version tag.
        """
        print(f"Getting release date for tag: {version_tag}")
        try:
            if self.honeypot_name == "conpot" and version_tag > "0.2.2":
                version_tag: str = f"Release_{version_tag}"
            release: GitRelease = self.repo.get_release(version_tag)
            return release.published_at.date()
        except Exception:
            print(f"\nRelease not found for tag: {version_tag}\n")
            # If not found then use the current datetime as the
            # release date, otherwise use return None
            return datetime.now().date()

    def get_cvss_score(self, cve: str) -> float | None:
        """
        Get the CVSS score for a given CVE.

        Args:
            cve (str): CVE ID to get the CVSS score for.

        Returns:
            float | None: Returns the CVSS score if found, None otherwise.
        """
        if not cve:
            return None

        url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        response: requests.Response = requests.get(url, params={'cveId': cve})
        time.sleep(2)  # Wait for 2 seconds to avoid rate limit

        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                cve = vulns[0].get("cve", {})
                metrics = cve.get("metrics", {})
                if metrics:
                    cvss_metric = (
                        metrics.get("cvssMetricV31", [])
                        or metrics.get("cvssMetricV3", [])
                        or metrics.get("cvssMetricV2", [])
                    )
                    if cvss_metric:
                        cvss_data = cvss_metric[0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore", float)
                        return cvss_score
        return None

    def process_vulnerabilities(self, packages: list[str]) -> VulnLibs:
        """
        Process the given packages to check for vulnerabilities using
        the vulnerability data.

        Args:
            packages (list[str]): The list of packages to process.

        Returns:
            VulnLibs: A dictionary of vulnerable libraries and their
                       associated vulnerabilities.
        """
        # Load vulnerability data from the downloaded JSON file
        with open(self.insecure_full_path, "r") as f:
            vuln_data: dict = json.load(f)

        # Custom vulnerability check
        vulnerable_libraries_dict: VulnLibs = {}
        vulnerable_libraries_dict: VulnLibs = {}
        for package in packages:
            name, installed_version = package.split("==")
            if name in vuln_data:
                for vuln in vuln_data[name]:
                    vuln_id: str | None = vuln["id"]
                    affected_versions: str = SpecifierSet(vuln["v"])
                    if installed_version in affected_versions:
                        cve: str | None = vuln.get("cve")
                        cvss_score: float | None = self.get_cvss_score(cve)
                        vulnerability = Vulnerability(
                            name=name,
                            installed_version=installed_version,
                            affected_versions=vuln["v"],
                            cve=cve,
                            vulnerability_id=vuln_id,
                            advisory=vuln.get("advisory"),
                            cvss_score=cvss_score
                        )
                        if name not in vulnerable_libraries_dict:
                            vulnerable_libraries_dict[name] = []
                        vulnerable_libraries_dict[name].append(vulnerability)

        return vulnerable_libraries_dict

    def check_vulnerable_libraries(self, version: str) -> VulnLibs:
        """
        Check the specified version of the honeypot for vulnerable
        libraries using the requirements file.

        Args:
            version (str): The version of the package to check.

        Returns:
            VulnLibs: A dictionary of vulnerable libraries and their
                      associated vulnerabilities.
        """
        file_name = f"{self.requirements_files_path}/{self.honeypot_name}-{version}-requirements.txt"

        # Read the requirements file and parse it into a list of
        # requirement objects
        with open(file_name, 'r') as f:
            requirements: ReqList = [pkg_resources.Requirement.parse(line)
                                     for line in f.readlines()]

        # Convert Requirement objects to strings in the format "name==version"
        packages: list[str] = [f"{req.name}=={req.specs[0][1]}"
                               for req in requirements]

        # Process the packages to check for vulnerabilities
        return self.process_vulnerabilities(packages)

    def log_cves_to_file(self, vulnerabilities: VulnLibs) -> None:
        """
        Append found CVEs to a file.

        Args:
            vulnerabilities (VulnLibs): Dictionary of vulnerable libraries
                                        and their associated vulnerabilities.
        """
        dir_path = os.path.dirname(self.all_cves_path)
        if not os.path.isdir(dir_path):
            os.makedirs(dir_path)

        with open(self.all_cves_path, 'a') as f:
            for vuln_list in vulnerabilities.values():
                for vuln in vuln_list:
                    if vuln.cve:
                        f.write(f"{vuln.cve}\n")

    def analyze_vulnerabilities(self,
                                version: str,
                                requirements_url: str) -> str:
        """
        Analyze the vulnerabilities in the specified version of the
        honeypot using the requirements file.

        Args:
            version (str): The version of the honeypot to check.
            requirements_url (str): The URL of the requirements.txt file.

        Returns:
            str: The summary of the vulnerabilities found in the
                 specified version of the honeypot.
        """
        VulnOutputMap: TypeAlias = dict[str, Vulnerability.VulnDict]
        VulnJSON: TypeAlias = dict[str, VulnOutputMap]

        success: bool = self.download_requirements(version, requirements_url)
        if success:
            vulnerabilities: VulnLibs = self.check_vulnerable_libraries(version)

            # Convert Vulnerability objects to dictionaries
            vulnerabilities_dict: VulnOutputMap = {}
            for name, vuln_list in vulnerabilities.items():
                vulnerabilities_dict[name] = [vuln.to_dict()
                                              for vuln in vuln_list]

            # Wrap the vulnerabilities_dict inside another dictionary with
            # the version key
            vulnerabilities_json: VulnJSON = {version: vulnerabilities_dict}

            if not os.path.isdir(self.analysis_results_path):
                os.makedirs(self.analysis_results_path)

            with open(f"{self.analysis_results_path}/{self.honeypot_name}-{version}-vulnerabilities.json", "w") as f:
                json.dump(vulnerabilities_json, f, indent=2)
            logging.info(f"\nVulnerability report saved to {self.honeypot_name}-{version}-vulnerabilities.json\n")

            # Log CVEs to file
            self.log_cves_to_file(vulnerabilities)

            # Print summary of vulnerabilities
            self.print_summary(vulnerabilities)
            return self.generate_summary_dict(vulnerabilities)
        else:
            logging.error("\nFailed to download requirements.txt\n")

    def print_summary(self, vulnerabilities: VulnLibs) -> None:
        """
        Print a summary of the found vulnerabilities.

        Args:
            vulnerabilities (VulnLibs): A dictionary of vulnerable libraries
                                        and their associated vulnerabilities.
        """
        print("\nVulnerability Analysis Summary:\n")
        for name, vuln_list in vulnerabilities.items():
            print(f"{Fore.YELLOW}{name}{Style.RESET_ALL}")
            for vuln in vuln_list:
                severity_color: str = Fore.WHITE
                severity_color: str = Fore.WHITE
                if vuln.cvss_score:
                    if vuln.cvss_score < 4.0:
                        severity_color = Fore.GREEN
                    elif 4.0 <= vuln.cvss_score < 7.0:
                        severity_color = Fore.YELLOW
                    else:
                        severity_color = Fore.RED
                print(f"  - {severity_color}{vuln.vulnerability_id} - {vuln.affected_versions} - {vuln.cve} - CVSS: {vuln.cvss_score}{Style.RESET_ALL}\n")

    def generate_summary(
            self,
            vulnerabilities: VulnLibs
            ) -> tuple[str, str]:
        """
        Generate a summary of the found vulnerabilities as a string.

        Args:
            vulnerabilities (VulnLibs): A dictionary of vulnerable libraries
                                        and their associated vulnerabilities.
        """
        actions_text: str = ""
        summary_text: str = "\nVulnerability Analysis Summary:\n"
        for name, vuln_list in vulnerabilities.items():
            summary_text += f"{name}\n"
            actions_text += f"{name}, "
            for vuln in vuln_list:
                severity_color: str
                severity_color: str
                if vuln.cvss_score:
                    if vuln.cvss_score < 4.0:
                        severity_color = "Green"
                    elif 4.0 <= vuln.cvss_score < 7.0:
                        severity_color = "Yellow"
                    else:
                        severity_color = "Red"
                else:
                    severity_color = "No CVSS Score"
                summary_text += f"  - {severity_color} {vuln.vulnerability_id} - {vuln.affected_versions} - {vuln.cve} - CVSS: {vuln.cvss_score}\n"
            summary_text += "\n"
        actions_text = f"All of these modules need to be updated:\n{actions_text[0:-2]}"
        return (summary_text, actions_text)
    
    def generate_summary_dict(self, vulnerabilities: VulnLibs) -> dict:
        """
        Generate a structured dictionary summary of the found vulnerabilities.

        Args:
            vulnerabilities (VulnLibs): A dictionary of vulnerable libraries
                                        and their associated vulnerabilities.
        
        Returns:
            dict: Structured vulnerability summary with detailed breakdown
        """
        summary = {
            "vulnerability_analysis": {
                "total_vulnerable_libraries": len(vulnerabilities),
                "libraries": {},
                "severity_breakdown": {
                    "critical": 0,    # CVSS >= 9.0
                    "high": 0,        # CVSS 7.0-8.9
                    "medium": 0,      # CVSS 4.0-6.9
                    "low": 0,         # CVSS < 4.0
                    "no_score": 0     # No CVSS score
                },
                "total_vulnerabilities": 0,
                "modules_to_update": [],
                "action_required": "",
            }
        }
        
        total_vulns = 0
        actions_text = ""

        for name, vuln_list in vulnerabilities.items():
            # Add to modules that need updating
            summary["vulnerability_analysis"]["modules_to_update"].append(name)
            actions_text += f"{name}, "
            
            # Process each vulnerability in this library
            library_vulns = []
            for vuln in vuln_list:
                total_vulns += 1
                
                # Determine severity category
                if vuln.cvss_score:
                    if vuln.cvss_score >= 9.0:
                        severity_category = "critical"
                    elif vuln.cvss_score >= 7.0:
                        severity_category = "high" 
                    elif vuln.cvss_score >= 4.0:
                        severity_category = "medium"
                    else:
                        severity_category = "low"
                    
                    # Update severity breakdown
                    summary["vulnerability_analysis"]["severity_breakdown"][severity_category] += 1
                else:
                    severity_category = "no_score"
                    summary["vulnerability_analysis"]["severity_breakdown"]["no_score"] += 1
                
                # Add vulnerability details
                vuln_details = {
                    "vulnerability_id": vuln.vulnerability_id,
                    "cve": vuln.cve,
                    "affected_versions": vuln.affected_versions,
                    "cvss_score": vuln.cvss_score,
                    "severity_category": severity_category
                }
                library_vulns.append(vuln_details)
            
            # Add library information
            summary["vulnerability_analysis"]["libraries"][name] = {
                "library_name": name,
                "vulnerability_count": len(vuln_list),
                "vulnerabilities": library_vulns
            }
        
        # Update total count
        summary["vulnerability_analysis"]["total_vulnerabilities"] = total_vulns
        
        # Generate action text
        if summary["vulnerability_analysis"]["modules_to_update"]:
            modules_list = ", ".join(summary["vulnerability_analysis"]["modules_to_update"])
            summary["vulnerability_analysis"]["action_required"] = f"All of these modules need to be updated: {modules_list}"
        else:
            summary["vulnerability_analysis"]["action_required"] = "No vulnerable libraries found - no action required"

        # Add actions_text
        summary["vulnerability_analysis"]["actions_text"] = f"All of these modules need to be updated:\n{actions_text[:-2]}"

        return summary
