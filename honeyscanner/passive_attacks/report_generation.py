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

