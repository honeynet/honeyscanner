import os
import re
import sys
import time
import json
import requests
from bs4 import BeautifulSoup
from github import Github
sys.path.append(os.path.dirname(os.path.abspath(os.path.join(__file__, os.pardir))))
from config import GITHUB_ACCESS_TOKEN
from colorama import Fore, Style, init

# python3 CVEAnalyzer.py to run but takes too much time!

class CVEAnalyzer:
    def __init__(self, input_file):
        init(autoreset=True)
        self.github = Github(GITHUB_ACCESS_TOKEN)
        # keep the name and version of the honeypot after the last '/' and remove _analysis.json
        self.report_file_name = input_file.split('/')[-1].split('_analysis.json')[0]
        self.input_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "analysis_results")
        self.input_file = os.path.join(self.input_folder, input_file)
        self.output_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "exploits")
        parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.all_cves_path = os.path.join(parent_dir, "results", "all_cves.txt")
        
    def extract_cwe_links(self):
        """
        Extract CWE links from the analysis results
        """
        print(Fore.GREEN + f"Extracting CWE links from {self.input_file}...")
        with open(self.input_file, 'r') as file:
            data = json.load(file)

        results = []
        for key in data:
            results.extend(data[key].get('results', []))
        
        cwe_links = []
        for result in results:
            cwe_link = result.get('issue_cwe', {}).get('link')
            if cwe_link:
                cwe_links.append(cwe_link)
        
        return cwe_links

    def scrape_cve_ids(self):
        """
        Scrape CVE IDs from CWE links
        """
        print(Fore.GREEN + f"Scraping CVE IDs from CWE links...")
        cve_ids = []
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}')
        for cwe_link in self.cwe_links:
            print(Fore.YELLOW + f"Scraping CVE IDs from {cwe_link}...")
            response = requests.get(cwe_link)
            if response.status_code == 200:
                cve_matches = cve_pattern.findall(response.text)
                for cve_id in cve_matches:
                    if cve_id not in cve_ids:
                        cve_ids.append(cve_id)
        
        return cve_ids

    def find_github_repos(self):
        """
        Find GitHub repos that contain the CVE IDs
        """
        print(Fore.GREEN + f"Finding GitHub repos that contain the CVE IDs...")
        repo_dict = {}
        for cve_id in self.cve_ids:
            print(Fore.YELLOW + f"Finding GitHub repos that contain {cve_id}...")
            query = f"{cve_id} in:path OR {cve_id} in:description OR {cve_id} in:name"
            repos = self.github.search_repositories(query=query, sort='stars', order='desc')
            time.sleep(5)  # Wait for 5 seconds to avoid rate limit
            if repos.totalCount > 0:
                best_repo = repos[0]
                repo_dict[cve_id] = {'name': best_repo.name, 'url': best_repo.html_url}
            else:
                repo_dict[cve_id] = None

        return repo_dict

    def save_to_file(self):
        """
        Save the results to a file
        """
        print(Fore.GREEN + f"Saving the results to a file...")
        if not os.path.exists(self.output_folder):
            os.mkdir(self.output_folder)
        output_file = os.path.join(self.output_folder, f'{self.report_file_name}_cve_github_repos.txt')
        with open(output_file, 'w') as file:
            for cve_id, repo in self.github_repos.items():
                file.write(f"{cve_id}: ")
                if repo:
                    file.write(f"{repo['url']}\n")
                else:
                    file.write("No PoC found on GitHub\n")
            file.write('\n')

    def log_cves_to_file(self):
        """
        Append found CVEs to a file.

        :return: None
        """
        print(Fore.GREEN + f"Logging CVEs to file {self.all_cves_path}...")
        
        dir_path = os.path.dirname(self.all_cves_path)
        if not os.path.isdir(dir_path):
            os.makedirs(dir_path)

        with open(self.all_cves_path, 'a') as file:
            for cve_id in self.cve_ids:
                file.write(f"{cve_id}\n")

    def run(self):
        """
        Run the CVE analyzer
        """
        self.cwe_links = self.extract_cwe_links()
        self.cve_ids = self.scrape_cve_ids()
        self.log_cves_to_file()
        self.github_repos = self.find_github_repos()
        self.save_to_file()
