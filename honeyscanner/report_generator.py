from pathlib import Path
# TODO: Fix this
# add actionable recommendations, overall score, read from thesis report

class ReportGenerator:
    def __init__(self, passive_results, active_results):
        self.passive_results = passive_results
        self.active_results = active_results
        self.report_path = Path(__file__).resolve().parent / "reports" / "report.txt"

    def generate_report(self):
        pass
        # report = self.passive_results + self.active_results
        # print(report)
        # self.report_path.write_text(report)


# import json
# import datetime

# def generate_report(honeypot_name, attack_results):
#     report_data = {
#         'honeypot_name': honeypot_name,
#         'date': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
#         'attack_results': attack_results,
#         'summary': generate_summary(attack_results)
#     }

#     # Save the report as a JSON file
#     save_report_to_file(report_data, honeypot_name)

#     return report_data

# def generate_summary(attack_results):
#     total_attacks = len(attack_results)
#     successful_attacks = sum(1 for result in attack_results if result['success'])

#     return {
#         'total_attacks': total_attacks,
#         'successful_attacks': successful_attacks,
#         'failed_attacks': total_attacks - successful_attacks,
#         'success_rate': successful_attacks / total_attacks * 100,
#     }

# def save_report_to_file(report_data, honeypot_name):
#     filename = f"{honeypot_name}_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

#     with open(filename, 'w') as report_file:
#         json.dump(report_data, report_file, indent=2)

