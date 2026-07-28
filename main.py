from collections import Counter


def read_log_file(file_path):
    with open(file_path, "r") as file:
        logs = file.readlines()

    return logs


def extract_ips(logs):
    ips = []

    for log in logs:
        if not log.strip():
            continue

        ip = log.split()[0]
        ips.append(ip)

    return ips


def detect_failed_logins(logs):
    failed_logins = {}

    for log in logs:
        if not log.strip():
            continue
    
        parts = log.split()

        ip = parts[0]
        status_code = parts[-1]

        if status_code == "401":
            if ip in failed_logins:
                failed_logins[ip] += 1
            else:
                failed_logins[ip] = 1

    return failed_logins

def detect_directory_scans(logs):
    suspicious_paths = [
        "/admin",
        "/.env",
        "/phpmyadmin",
        "/wp-login.php"
    ]

    alerts = []

    for log in logs:
        if not log.strip():
            continue

        parts = log.split()

        ip = parts[0]

        for path in suspicious_paths:
            if path in log:
                alerts.append({
                    "type": "Directory Scan",
                    "ip": ip,
                    "target": path,
                    "severity": "Medium"
                })

    return alerts

def generate_alerts(failed_attempts):
    alerts = []

    for ip, count in failed_attempts.items():
        if count >= 3:
            alert = {
                "type": "Brute Force Attack",
                "ip": ip,
                "attempts": count,
                "severity": "Medium"
            }

            alerts.append(alert)

    return alerts


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

scan_alerts = detect_directory_scans(logs)

print("\nDirectory Scan Alerts")

for alert in scan_alerts:
    print("\n🚨", alert["type"])
    print("IP:", alert["ip"])
    print("Target:", alert["target"])
    print("Severity:", alert["severity"])