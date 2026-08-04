from collections import Counter
from parser import read_log_file, extract_ips
from detectors import (
    detect_failed_logins,
    generate_alerts,
    detect_directory_scans,
)

from reporting import export_to_json
import json
import os


log_file = "logs/sample.log"

logs = read_log_file(log_file)

print("Number of log entries:", len(logs))


ips = extract_ips(logs)

ip_counter = Counter(ips)

print("\nIP Address Frequency")

for ip, count in ip_counter.items():
    print(ip, ":", count)


failed_attempts = detect_failed_logins(logs)

print("\nFailed Login Attempts")

for ip, count in failed_attempts.items():
    print(ip, ":", count)


alerts = generate_alerts(failed_attempts)

print("\nSecurity Alerts")

for alert in alerts:
    print("\n🚨", alert["type"])
    print("IP:", alert["ip"])
    print("Attempts:", alert["attempts"])
    print("Severity:", alert["severity"])
    print("MITRE ATT&CK:", alert["mitre_id"], "-", alert["mitre_name"])


directory_alerts = detect_directory_scans(logs)

print("\nDirectory Scan Alerts")

for alert in directory_alerts:
    print("\n🚨", alert["type"])
    print("IP:", alert["ip"])
    print("Target:", alert["target"])
    print("Attempts:", alert["attempts"])
    print("Severity:", alert["severity"])
    print("MITRE ATT&CK:", alert["mitre_id"], "-", alert["mitre_name"])


export_to_json(alerts, directory_alerts)