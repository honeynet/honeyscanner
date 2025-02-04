from datetime import datetime
from honeypots import BaseHoneypot
from jinja2 import Environment, FileSystemLoader, Template
from pathlib import Path
from typing import TypeAlias

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
        self.parent_path = Path(__file__).resolve().parent
        self.report_path: Path = self.parent_path / "reports"
        env = Environment(loader=FileSystemLoader(self.report_path))
        self.template: Template = env.get_template("master.jinja")

    def count_all_cves(self) -> int:
        """
        Counts the number of unique CVEs in the all_cves.txt file.

        Returns:
            int: The number of unique CVEs.
        """
        path_to_all_cves: Path = self.parent_path / "passive_attacks" / "results" / "all_cves.txt"
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
                 active_results: ReportResults) -> None:
        """
        Generate the report.

        Args:
            passive_results (str): Passive detection results.
            active_results (ReportResults): Active attacks results.
        """
        date: str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        report_date: str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        """total_attacks: int = active_results[1]
        attack_success: int = active_results[2]
        success_rate: str = f"{(attack_success / total_attacks) * 100:.2f}%
        """
        ########
        total_attacks: int = active_results[1] if active_results else 0
        attack_success: int = active_results[2] if active_results else 0
        success_rate: str = f"{(attack_success / total_attacks) * 100:.2f}%" if total_attacks > 0 else "N/A"

        print("Generating report...")

        # Build the context dictionary
        context = {
            "name": self.honeypot.name,
            "version": self.honeypot.version,
            "ip": self.honeypot.ip,
            "port": self.honeypot.ports,
            "date": report_date,
            "all_cves": self.count_all_cves(),
            "success": attack_success,
            "failed": total_attacks - attack_success,
            "rating":success_rate
        }

        # Conditionally add active_results and passive_results
        if active_results:
            context["active_results"] = active_results[0]
        if passive_results:
            context["passive_results"] = passive_results
            context["recommendations"] = recommendations

        report: str = self.template.render(**context)

        #print("Generating report...")
        """report: str = self.template.render(
                        name=self.honeypot.name,
                        version=self.honeypot.version,
                        ip=self.honeypot.ip,
                        port=self.honeypot.ports,
                        date=report_date,
                        passive_results=passive_results,
                        active_results=active_results[0],
                        all_cves=self.count_all_cves(),
                        success=attack_success,
                        failed=total_attacks - attack_success,
                        rating=success_rate,
                        recommendations=recommendations)"""
        new_report_path: Path = self.report_path / f"report_{date}.txt"
        new_report_path.write_text(report)
        print(f"Report generated successfully at {new_report_path}")
