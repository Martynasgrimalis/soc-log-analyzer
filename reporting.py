import os
import json

def export_to_json(brute_force_alerts, directory_alerts):
    os.makedirs("reports", exist_ok=True)

    all_alerts = brute_force_alerts + directory_alerts

    with open("reports/security_alerts.json", "w") as file:
        json.dump(all_alerts, file, indent=4)

    print("\nJSON report saved:")
    print("reports/security_alerts.json")