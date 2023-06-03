import os
import sys
import json
import time
import requests
import datetime
from packaging.version import parse as pkg_version_parse
from packaging.specifiers import SpecifierSet
from github import Github
import pkg_resources
import logging
import functools
from collections import defaultdict
from colorama import Fore, Style, init
from pathlib import Path

from .models import Vulnerability

class VulnerableLibrariesAnalyzer:
    def __init__(self, honeypot_name, owner, repo_name):
        logging.basicConfig(level=logging.INFO, format="%(message)s")
        init(autoreset=True)
        self.honeypot_name = honeypot_name
        self.owner = owner
        self.repo_name = repo_name
        self.repo = self.get_repo()
        self.insecure_full_path = Path(__file__).resolve().parent / "vuln_database" / "insecure_full.json"
        self.analysis_results_path = Path(__file__).resolve().parent / "analysis_results"
        self.requirements_files_path = Path(__file__).resolve().parent / "requirements_files"
        self.all_cves_path = Path(__file__).resolve().parent.parent / "results" / "all_cves.txt"
        self.download_insecure_full_json()
        self.vuln_data_cache = defaultdict(dict)

    def get_repo(self):
        """
        Get the repository object for the specified owner and repo_name.
        """
        g = Github()
        user = g.get_user(self.owner)
        return user.get_repo(self.repo_name)

    def download_insecure_full_json(self):
        """
        Download the insecure_full.json file containing vulnerability data.
        """
        url = "https://raw.githubusercontent.com/pyupio/safety-db/master/data/insecure_full.json"
        response = requests.get(url)
        if response.status_code == 200:
            if not self.insecure_full_path.parent.is_dir():
                self.insecure_full_path.parent.mkdir()

            with open(self.insecure_full_path, "w") as f:
                f.write(response.text)
        else:
            logging.error("\nFailed to download the insecure_full.json file\n")
            exit(1)

    def get_latest_version_before_date(self, package_name, date):
        """
        Get the latest version of the package released before the specified date.
        """
        url = f"https://pypi.org/pypi/{package_name}/json"
        response = requests.get(url)
        if response.status_code == 200:
            package_data = response.json()
            releases = package_data["releases"]
            latest_version = None
            for release_version in releases:
                try:
                    if not releases[release_version] or "upload_time" not in releases[release_version][0]:
                        continue
                    release_date_str = releases[release_version][0]["upload_time"]
                    release_date_obj = datetime.datetime.strptime(release_date_str, "%Y-%m-%dT%H:%M:%S")
                    if release_date_obj.date() <= date:
                        if not latest_version or pkg_version_parse(release_version) > pkg_version_parse(latest_version):
                            latest_version = release_version
                except Exception as e:
                    print(f"Error processing {package_name} version {release_version}: {e}")
            return latest_version
        return None

    def update_versions(self, requirements, release_date):
        """
        Update the versions in the requirements list to the latest version before the release date.
        """
        updated_requirements = []
        for req in requirements:
            spec = req.specs[0] if req.specs else None
            if spec:
                operator, version = spec
                if operator in (">=", "<="):
                    latest_version = self.get_latest_version_before_date(req.name, release_date)
                    if latest_version:
                        updated_requirements.append(f"{req.name}=={latest_version}")
                    else:
                        updated_requirements.append(f"{req.name}=={version}")
                else:
                    updated_requirements.append(str(req))
            else:
                latest_version = self.get_latest_version_before_date(req.name, release_date)
                if latest_version:
                    updated_requirements.append(f"{req.name}=={latest_version}")
                else:
                    updated_requirements.append(str(req))

        return updated_requirements


    def download_requirements(self, version, requirements_url):
        """
        Download the requirements.txt file and update the versions to the latest version before the release date.
        """
        release_date = self.get_release_date(version)
        response = requests.get(requirements_url)
        if response.status_code == 200:
            requirements = list(pkg_resources.parse_requirements(response.text))
            updated_requirements = self.update_versions(requirements, release_date)
            with open(f"{self.requirements_files_path}/{self.honeypot_name}-{version}-requirements.txt", "w") as f:
                f.write("\n".join(updated_requirements))
            return True
        return False


    def get_release_date(self, version_tag):
        """
        Get the release date of the specified version tag.
        """
        try:
            release = self.repo.get_release(version_tag)
            return release.published_at.date()
        except github.GithubException.UnknownObjectException:
            print(f"\nRelease not found for tag: {version_tag}\n")
            # If not found then use the current datetime as the release date, otherwise use return None
            return datetime.datetime.now().date()

    def get_cvss_score(self, cve):
        """
        Get the CVSS score for a given CVE.
        """
        if not cve:
            return None

        url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve}"
        response = requests.get(url)
        time.sleep(2)  # Wait for 2 seconds to avoid rate limit

        if response.status_code == 200:
            data = response.json()
            if 'result' in data:
                cve_item = data['result']['CVE_Items'][0]
                impact = cve_item.get('impact', {})
                base_metrics = impact.get('baseMetricV3', {}) or impact.get('baseMetricV2', {})
                cvss_score = base_metrics.get('cvssV3', {}).get('baseScore') or base_metrics.get('cvssV2', {}).get('baseScore')
                return cvss_score

        return None

    @staticmethod
    def convert_vuln_data_format(json_data):
        """
        Convert vulnerability data from the downloaded JSON file to a more convenient format.
        """
        converted_data = {}
        for package_name, vulnerabilities in json_data.items():
            for vuln in vulnerabilities:
                vuln_id = vuln["id"]
                specs = vuln["specs"]

                if package_name not in converted_data:
                    converted_data[package_name] = []

                converted_data[package_name].append({
                    "id": vuln_id,
                    "v": ",".join(specs)
                })

        return converted_data

    def process_vulnerabilities(self, packages):
        """
        Process the given packages to check for vulnerabilities using the vulnerability data.
        """
        # Load vulnerability data from the downloaded JSON file
        with open(self.insecure_full_path, "r") as f:
            vuln_data = json.load(f)

        # Custom vulnerability check
        vulnerable_libraries_dict = {}
        for package in packages:
            name, installed_version = package.split("==")
            if name in vuln_data:
                for vuln in vuln_data[name]:
                    vuln_id = vuln["id"]
                    affected_versions = SpecifierSet(vuln["v"])
                    if installed_version in affected_versions:
                        cve = vuln.get("cve")
                        cvss_score = self.get_cvss_score(cve)
                        vulnerability = Vulnerability(
                            name=name,
                            installed_version=installed_version,
                            affected_versions=vuln["v"],
                            cve=cve,
                            vulnerability_id=vuln["id"],
                            advisory=vuln.get("advisory"),
                            cvss_score=cvss_score
                        )
                        if name not in vulnerable_libraries_dict:
                            vulnerable_libraries_dict[name] = []
                        vulnerable_libraries_dict[name].append(vulnerability)

        return vulnerable_libraries_dict

    def check_vulnerable_libraries(self, version):
        """
        Check the specified version of the honeypot for vulnerable libraries using the requirements file.
        """
        file_name = f"{self.requirements_files_path}/{self.honeypot_name}-{version}-requirements.txt"

        # Read the requirements file and parse it into a list of Requirement objects
        with open(file_name, 'r') as f:
            requirements = [pkg_resources.Requirement.parse(line) for line in f.readlines()]

        # Convert Requirement objects to strings in the format "name==version"
        packages = [f"{req.name}=={req.specs[0][1]}" for req in requirements]

        # Process the packages to check for vulnerabilities
        return self.process_vulnerabilities(packages)

    def log_cves_to_file(self, vulnerabilities):
        """
        Append found CVEs to a file.
        """
        dir_path = os.path.dirname(self.all_cves_path)
        if not os.path.isdir(dir_path):
            os.makedirs(dir_path)
        
        with open(self.all_cves_path, 'a') as f:
            for vuln_list in vulnerabilities.values():
                for vuln in vuln_list:
                    if vuln.cve:
                        f.write(f"{vuln.cve}\n")

    def analyze_vulnerabilities(self, version, requirements_url):
        """
        Analyze the vulnerabilities in the specified version of the honeypot using the requirements file.
        """
        success = self.download_requirements(version, requirements_url)
        if success:
            vulnerabilities = self.check_vulnerable_libraries(version)

            # Convert Vulnerability objects to dictionaries
            vulnerabilities_dict = {}
            for name, vuln_list in vulnerabilities.items():
                vulnerabilities_dict[name] = [vuln.to_dict() for vuln in vuln_list]

            # Wrap the vulnerabilities_dict inside another dictionary with the version key
            vulnerabilities_json = {version: vulnerabilities_dict}

            if not os.path.isdir(self.analysis_results_path):
                os.makedirs(self.analysis_results_path)

            with open(f"{self.analysis_results_path}/{self.honeypot_name}-{version}-vulnerabilities.json", "w") as f:
                json.dump(vulnerabilities_json, f, indent=2)
            logging.info(f"\nVulnerability report saved to {self.honeypot_name}-{version}-vulnerabilities.json\n")

            # Log CVEs to file
            self.log_cves_to_file(vulnerabilities)

            # Print summary of vulnerabilities
            self.print_summary(vulnerabilities)
        else:
            logging.error("\nFailed to download requirements.txt\n")


    def print_summary(self, vulnerabilities):
        """
        Print a summary of the found vulnerabilities.
        """
        print("\nVulnerability Analysis Summary:\n")
        for name, vuln_list in vulnerabilities.items():
            print(f"{Fore.YELLOW}{name}{Style.RESET_ALL}")
            for vuln in vuln_list:
                severity_color = Fore.WHITE
                if vuln.cvss_score:
                    if vuln.cvss_score < 4.0:
                        severity_color = Fore.GREEN
                    elif 4.0 <= vuln.cvss_score < 7.0:
                        severity_color = Fore.YELLOW
                    else:
                        severity_color = Fore.RED
                print(f"  - {severity_color}{vuln.vulnerability_id} - {vuln.affected_versions} - {vuln.cve} - CVSS: {vuln.cvss_score}{Style.RESET_ALL}")
            print()
    
    # Functions for the patch_manager - Not tested yet
    # ------------------------------------------------
    # 
    # def get_suggested_upgrades(self, vulnerabilities):
    #     """
    #     Get suggested upgrades for vulnerable libraries.

    #     :param vulnerabilities: Dictionary of vulnerable libraries and their vulnerability information
    #     :return: Dictionary of suggested upgrades
    #     """
    #     suggested_upgrades = {}
    #     for library, vuln_list in vulnerabilities.items():
    #         current_version = vuln_list[0]['installed_version']
    #         safe_versions = set()
    #         for vuln in vuln_list:
    #             affected_versions = SpecifierSet(vuln['affected_versions'])
    #             # If the current version is not affected, add it to the safe versions
    #             safe_versions |= set(str(v) for v in (affected_versions & SpecifierSet(f">={current_version}")))
    #         if safe_versions:
    #             suggested_upgrades[library] = str(sorted(safe_versions, key=pkg_version_parse)[-1])
    #     return suggested_upgrades

    # def find_latest_requirements_file(self):
    #     """
    #     Find the latest requirements file in the requirements_files directory.

    #     :return: File name of the latest requirements file
    #     """
    #     files = os.listdir(self.requirements_files_path)
    #     return max(files, key=lambda x: pkg_version_parse(x.split('-')[1]))

    # def apply_library_upgrades(self, requirements_file, suggested_upgrades):
    #     """
    #     Apply the suggested library upgrades to the requirements file.

    #     :param requirements_file: Name of the requirements file
    #     :param suggested_upgrades: Dictionary of suggested upgrades
    #     :return: None
    #     """
    #     with open(os.path.join(self.requirements_files_path, requirements_file), "r") as f:
    #         requirements = [pkg_resources.Requirement.parse(line) for line in f.readlines()]

    #     updated_requirements = []
    #     for req in requirements:
    #         if req.name in suggested_upgrades:
    #             updated_requirements.append(pkg_resources.Requirement.parse(f"{req.name}=={suggested_upgrades[req.name]}"))
    #         else:
    #             updated_requirements.append(req)

    #     return updated_requirements
    
    # def check_vulnerabilities(self, requirements):
    #     """
    #     Check for vulnerable libraries in the given requirements.

    #     :param requirements: List of pkg_resources.Requirement objects
    #     :return: Dictionary of vulnerable libraries and their vulnerability information
    #     """
    #     vulnerabilities = {}
    #     for req in requirements:
    #         package_str = f"{req.name}=={req.specs[0][1]}"
    #         library_vulnerabilities = self.process_vulnerabilities([package_str])
    #         if library_vulnerabilities:
    #             vulnerabilities[req.name] = library_vulnerabilities[req.name]
    #     return vulnerabilities

