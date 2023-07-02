from pathlib import Path
import datetime

# add actionable recommendations, overall score, read from thesis report

def ascii_art_honeyscanner():
    ascii_art = r"""

  ___ ___                                                                             
 /   |   \  ____   ____   ____ ___.__. ______ ____ _____    ____   ____   ___________ 
/    ~    \/  _ \ /    \_/ __ <   |  |/  ___// ___\\__  \  /    \ /    \_/ __ \_  __ \
\    Y    (  <_> )   |  \  ___/\___  |\___ \\  \___ / __ \|   |  \   |  \  ___/|  | \/
 \___|_  / \____/|___|  /\___  > ____/____  >\___  >____  /___|  /___|  /\___  >__|   
       \/             \/     \/\/         \/     \/     \/     \/     \/     \/       

        """
    return ascii_art

class ReportGenerator:
    def __init__(self, honeypot):
        self.honeypot = honeypot
        self.report_path = Path(__file__).resolve().parent / "reports" / "report.txt"

    def count_all_cves(self):
        path_to_all_cves = Path(__file__).resolve().parent / "passive_attacks" / "results" / "all_cves.txt"
        lines_seen = set()
        unique_lines = []
        with open(path_to_all_cves, "r") as f:
            for line in f:
                if line not in lines_seen:
                    unique_lines.append(line)
                    lines_seen.add(line)
        return len(unique_lines)

    def generate_report(self, passive_results, active_results):
        print("Generating report...")
        report = ascii_art_honeyscanner()
        report += "\n\n"
        report += f"Security Assessment of {self.honeypot.name} Honeypot, Version: {self.honeypot.version} \n"
        report += f"Honeypot IP: {self.honeypot.ip} \n"
        report += f"Honeypot Port: {self.honeypot.port} \n"
        report += f"Date of Assessment: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} \n"
        report += f"Report Summary\n"
        report += f"Passive Attacks Results: \n"
        report += f"======================== \n"
        report += f"{passive_results} \n"
        report += f"Active Attacks Results: \n"
        report += f"======================= \n"
        report += f"{active_results} \n"
        report += f"Overall Score: \n"
        report += f"============== \n"
        report += f"TODO: Add overall score \n"
        report += f"\n\n"
        report += f"Successful Attacks: \n"
        report += f"=================== \n"
        report += f"TODO: Add successful attacks \n"
        report += f"\n\n"
        report += f"Failed Attacks: \n"
        report += f"================ \n"
        report += f"TODO: Add failed attacks \n"
        report += f"\n\n"
        report += f"Attack Success Rate: \n"
        report += f"==================== \n"
        report += f"TODO: Add attack success rate \n"
        report += f"\n\n"
        report += f"Total Potential CVEs: {self.count_all_cves()} \n"
        report += f"\n\n"
        report += f"Actionable Recommendations: \n"
        report += f"=========================== \n"
        report += f"TODO: Add actionable recommendations \n"
        report += f"\n\n"
        report += f"Detailed Report: \n"
        report += f"================ \n"
        report += f"TODO: Add detailed report \n"
        report += f"\n\n"
        print(report)
        self.report_path.write_text(report)
        print(f"Report generated successfully at {self.report_path}")
        return report
