from datetime import datetime
from honeyscanner.honeypots import BaseHoneypot
from jinja2 import Environment, FileSystemLoader, Template
from pathlib import Path
from typing import TypeAlias
import tempfile

# add actionable recommendations, overall score, read from thesis report
ReportResults: TypeAlias = tuple[str, int, int]


class ReportGenerator:
    def __init__(self, honeypot: BaseHoneypot) -> None:
        """
        Initializes a new instance of the ReportGenerator object.

        Args:
            honeypot (BaseHoneypot): Honeypot object to get the information
                                     like the name, version, etc from for
                                     the report.
        """
        self.honeypot = honeypot

        base_temp = Path(tempfile.gettempdir())
        self.parent_path: Path = base_temp / "honeyscanner"


        
        # self.report_path: Path = self.parent_path / "reports"
        # env = Environment(loader=FileSystemLoader(self.report_path))
        # self.template: Template = env.get_template("master.jinja")

    def count_all_cves(self) -> int:
        """
        Counts the number of unique CVEs in the all_cves.txt file.

        Returns:
            int: The number of unique CVEs.
        """
        path_to_all_cves: Path = self.parent_path / "results" / "all_cves.txt"
        lines_seen: set[str] = set()
        unique_lines: list[str] = []
        with open(path_to_all_cves, "r") as f:
            for line in f:
                if line not in lines_seen:
                    unique_lines.append(line)
                    lines_seen.add(line)
        return len(unique_lines)

    def generate(self,
             recommendations: list[str],
             passive_results: str,
             active_results: ReportResults) -> dict:
        """
        Generate the report as a dictionary.

        Args:
            recommendations (list[str]): List of recommendations.
            passive_results (str): Passive detection results.
            active_results (ReportResults): Active attacks results.

        Returns:
            dict: A dictionary containing the report details and content.
        """
        date: str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        report_date: str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        report_dict = {
            "metadata": {
                "report_date": report_date,
                "filename": f"report_{date}.txt",
                "honeypot": {
                    "name": self.honeypot.name,
                    "version": self.honeypot.version,
                    "ip": self.honeypot.ip,
                    "ports": list(self.honeypot.ports)
                }
            },
            "results": {
                "passive": passive_results,
                "active": active_results[0],
                "cves": self.count_all_cves(),
            },
            "recommendations": recommendations,
        }
        
        return report_dict
