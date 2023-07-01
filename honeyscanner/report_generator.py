from pathlib import Path
# TODO: Improve it in the future
# add actionable recommendations, overall score, read from thesis report

class ReportGenerator:
    def __init__(self, passive_results, active_results):
        self.passive_results = passive_results
        self.active_results = active_results
        self.report_path = Path(__file__).resolve().parent / "reports" / "report.txt"

    def generate_report(self):
        report = self.passive_results + self.active_results
        print(report)
        self.report_path.write_text(report)
