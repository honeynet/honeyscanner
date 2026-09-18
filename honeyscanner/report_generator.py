import copy
from datetime import datetime
import json
from pathlib import Path
import tempfile
from typing import TypeAlias

from honeyscanner.honeypots import BaseHoneypot

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

    def count_all_cves(self) -> int:
        """
        Counts the number of unique CVEs in the all_cves.txt file.

        Returns:
            int: The number of unique CVEs.
        """
        path_to_all_cves: Path = self.parent_path / "results" / "all_cves.txt"
        if not path_to_all_cves.exists():
            return 0
        lines_seen: set[str] = set()
        unique_lines: list[str] = []
        with open(path_to_all_cves, "r") as f:
            for line in f:
                if line not in lines_seen:
                    unique_lines.append(line)
                    lines_seen.add(line)
        return len(unique_lines)

    def generate(
        self,
        recommendations: list[str],
        passive_results: str,
        active_results: ReportResults,
    ) -> dict:
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
                    "ports": list(self.honeypot.ports),
                },
            },
            "results": {
                "passive": passive_results,
                "active": active_results[0],
                "cves": self.count_all_cves(),
            },
            "recommendations": recommendations,
        }

        return report_dict

    def save_json(
        self,
        report_dict: dict,
        output_dir: Path | None = None,
    ) -> Path:
        """
        Save the generated report dictionary as a JSON file.

        Args:
            report_dict (dict): The report dict returned by generate().
            output_dir (Path | None): Optional directory path to save to.
                Defaults to self.parent_path ("<temp>/honeyscanner").

        Returns:
            Path: The path to the saved JSON file.
        """
        target_dir = output_dir if output_dir is not None else self.parent_path
        target_dir.mkdir(parents=True, exist_ok=True)

        meta = report_dict.get("metadata", {})
        raw_filename = meta.get("filename", "report.json")
        filename = str(raw_filename)
        if filename.endswith(".txt"):
            filename = filename[:-4] + ".json"
        elif not filename.endswith(".json"):
            filename = f"{filename}.json"

        filepath: Path = target_dir / filename
        report_to_save = copy.deepcopy(report_dict)
        if "metadata" in report_to_save and isinstance(
            report_to_save["metadata"], dict
        ):
            report_to_save["metadata"]["filename"] = filename

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_to_save, f, indent=4, ensure_ascii=False)

        return filepath
