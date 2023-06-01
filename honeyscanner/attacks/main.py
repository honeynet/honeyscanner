import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from attack_orchestrator import AttackOrchestrator
from honeypots import Cowrie

# TODO: Add some nice interface between attacks to show progress like vulnanalyzer
# write results into file

def main():
    honeypot = Cowrie(
        version="2.1.0",
        ip="127.0.0.1",
        port=2222,
        username="root",
        password="123",
    )

    orchestrator = AttackOrchestrator(honeypot)
    results = orchestrator.run_attacks()
    report = orchestrator.generate_report(results)
    print(report)

if __name__ == "__main__":
    main()
