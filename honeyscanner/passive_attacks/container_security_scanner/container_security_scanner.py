import json
import os
import requests
import subprocess
from pathlib import Path
from shutil import rmtree
from colorama import Fore, Style, init

SEVERITY_LEVELS = 'MEDIUM,HIGH,CRITICAL'
# explore the documentation of trivy and see if you can add more features to this script
# now it checks for some vulnerabilities and secrets in the repo and also if available checks the docker image

class ContainerSecurityScanner:
    def __init__(self, honeypot_owner: str, honeypot_name: str) -> None:
        init(autoreset=True)
        self.honeypot_owner = honeypot_owner
        if self.honeypot_owner == "DinoTools":
            self.honeypot_owner = "dinotools"
        self.honeypot_name = honeypot_name
        self.github_repo_url = f"https://github.com/{honeypot_owner}/{honeypot_name}"
        self.local_repo_path = None
        self.base_path = Path(__file__).resolve().parent
        self.output_folder = self.base_path / "analysis_results"
        self.all_cves_path = self.base_path.parent / "results" / "all_cves.txt"
        self.trivy_path = self.base_path.parent.parent / "bin" / "trivy"
        self.report_name = self.output_folder / f"trivy_scan_results_{self.honeypot_name}.json"
        self.results = None 
        
    def check_trivy_installed(self) -> bool:
        """
        Check if Trivy is installed.
        """
        try:
            subprocess.check_output([str(self.trivy_path), '--version'])
            return True
        except FileNotFoundError:
            return False

    @staticmethod
    def install_trivy() -> None:
        """
        Install Trivy.
        """
        print(f"{Fore.GREEN}Installing Trivy...{Style.RESET_ALL}")
        curl_command = ["curl", "-sfL", "https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh"]
        sh_command = ["sh"]

        try:
            curl_process = subprocess.Popen(curl_command, stdout=subprocess.PIPE)
            sh_process = subprocess.run(sh_command, stdin=curl_process.stdout, check=True)
            curl_process.stdout.close()
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}Error installing Trivy: {e.output}")
            raise

    def clone_repository(self) -> None:
        """
        Clone the GitHub repository.
        """
        print(f"{Fore.GREEN}Cloning repository...{Style.RESET_ALL}")
        self.local_repo_path = Path.cwd() / self.github_repo_url.split("/")[-1].replace(".git", "")

        if self.local_repo_path.exists():
            rmtree(self.local_repo_path)

        clone_command = ['git', 'clone', self.github_repo_url]
        try:
            subprocess.run(clone_command, check=True)
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}Error cloning repository: {e.output}")
            raise

    @staticmethod
    def get_dockerhub_image(image_name: str) -> bool:
        """
        Check if the image exists on Docker Hub.
        """
        url = f"https://hub.docker.com/v2/repositories/{image_name}/tags/"
        response = requests.get(url)
        return response.status_code == 200

    def print_summary(self, results: dict) -> None:
        """
        Print a summary of the scan results.
        """
        print(f"{Fore.GREEN}Scan Summary{Style.RESET_ALL}")
        for target in results.get('Results', []):
            self._print_target_summary(target, 'Vulnerabilities')
            self._print_target_summary(target, 'Secrets')

    @staticmethod
    def _print_target_summary(target: dict, key: str) -> None:
        """
        Print a summary of either vulnerabilities or secrets for a target.
        """
        print(f"\n{Fore.CYAN}{key} in {target['Target']}:{Style.RESET_ALL}")
        for severity in SEVERITY_LEVELS.split(','):
            count = sum(1 for v in target.get(key, []) if v['Severity'] == severity)
            print(f"{severity}: {count}")

    def save_report(self, results: dict) -> None:
        """
        Save the scan results to a JSON file.
        """
        print(f"{Fore.GREEN}Saving report...{Style.RESET_ALL}")
        with open(self.report_name, 'w') as outfile:
            json.dump(results['Results'], outfile, indent=2)

    def cve_finder(self):
        """
        Find CVEs from the analysis results
        """
        print(f"{Fore.GREEN}Searching for exploits for CVEs in {self.report_name}...")
        with open(self.report_name, "r") as f:
            data = json.load(f)
        
        cve_ids = []
        for entry in data:
            vulnerabilities = entry.get("Vulnerabilities", [])
            for vulnerability in vulnerabilities:
                cve_id = vulnerability["VulnerabilityID"]                    
                cve_ids.append(cve_id)

        if not self.all_cves_path.exists():
            self.all_cves_path.touch()
            
        with open(self.all_cves_path, 'a') as file:
            for cve_id in cve_ids:
                file.write(f"{cve_id}\n")

    def cleanup(self) -> None:
        """
        Clean up the local repository and Trivy installation.
        """
        print(f"{Fore.GREEN}Cleaning up...{Style.RESET_ALL}")
        if self.local_repo_path and self.local_repo_path.exists():
            rmtree(self.local_repo_path)

        if self.check_trivy_installed():
            rmtree(Path(__file__).resolve().parent.parent.parent / "bin")

    def scan_repository(self) -> None:
        """
        Scan the repository for vulnerabilities and secrets.
        """
        self.check_trivy_installed()

        print(f"{Fore.GREEN}Scanning repository starts...{Style.RESET_ALL}")
        self.output_folder.mkdir(parents=True, exist_ok=True)
        if not self.check_trivy_installed():
            self.install_trivy()
        if not self.local_repo_path:
            self.clone_repository()

        scan_command = ""
        image_name = f"{self.honeypot_owner}/{self.honeypot_name}"

        if self.get_dockerhub_image(image_name):
            print(f"{Fore.GREEN}Docker image found on Docker Hub. I will scan the image.{Style.RESET_ALL}")
            scan_command_image = [self.trivy_path, 'image', image_name, '--exit-code', '0', '--severity', 'MEDIUM,HIGH,CRITICAL', '--format', 'json']
            scan_command = scan_command_image
        else:
            print(f"{Fore.YELLOW}Docker image not found on Docker Hub. I will just search for secrets.{Style.RESET_ALL}")
            scan_command_fs = [self.trivy_path, 'fs', str(self.local_repo_path), '--exit-code', '0', '--severity', 'MEDIUM,HIGH,CRITICAL', '--format', 'json']
            scan_command = scan_command_fs

        try:
            output = subprocess.check_output(scan_command).decode()
            results = json.loads(output)
            self.print_summary(results)
            self.save_report(results)
            self.cve_finder()
            self.results = results
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}Error scanning repository: {e.output}")
            raise
        finally:
            self.cleanup()
            return self.generate_summary(results)
    
    def generate_summary(self, results: dict) -> str:
        """
        Generate a summary of the scan results as a string.
        """
        summary_text = "Scan Summary\n"
        for target in results.get('Results', []):
            summary_text += self._generate_target_summary(target, 'Vulnerabilities')
            summary_text += self._generate_target_summary(target, 'Secrets')

        return summary_text

    @staticmethod
    def _generate_target_summary(target: dict, key: str) -> str:
        """
        Generate a summary of either vulnerabilities or secrets for a target as a string.
        """
        summary_text = f"\n{key} in {target['Target']}:\n"
        for severity in SEVERITY_LEVELS.split(','):
            count = sum(1 for v in target.get(key, []) if v['Severity'] == severity)
            summary_text += f"{severity}: {count}\n"

        return summary_text
