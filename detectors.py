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

    scan_counts = {}

    for log in logs:
        if not log.strip():
            continue

        parts = log.split()

        ip = parts[0]

        for path in suspicious_paths:
            if path in log:

                key = (ip, path)

                if key in scan_counts:
                    scan_counts[key] += 1
                else:
                    scan_counts[key] = 1


    alerts = []

    for (ip, path), count in scan_counts.items():

        if path == "/.env":
            severity = "High"

        elif path in ["/phpmyadmin", "/wp-login.php"]:
            severity = "High"

        elif path == "/admin":
            severity = "Medium"

        else:
            severity = "Low"


        alerts.append({
            "type": "Directory Scan",
            "ip": ip,
            "target": path,
            "attempts": count,
            "severity": severity,
            "mitre_id": "T1595",
            "mitre_name": "Active Scanning"
        })


    return alerts

def generate_alerts(failed_attempts):
    alerts = []

    for ip, count in failed_attempts.items():
        if count >= 10:
            severity = "High"

        elif count >= 5:
            severity = "Medium"

        elif count >= 3:
            severity = "Low"

        else:
            continue

        alert = {
            "type": "Brute Force Attack",
            "ip": ip,
            "attempts": count,
            "severity": severity,
            "mitre_id": "T1110",
            "mitre_name": "Brute Force"
 }

        alerts.append(alert)

    return alerts