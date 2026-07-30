# SOC Log Analyzer

Python-based security log analysis tool designed to detect suspicious activity, generate security alerts, classify severity levels and map detected threats to MITRE ATT&CK techniques.

The project simulates basic SOC analyst workflows: log investigation, threat detection, alert prioritization and security reporting.

## Features

- Parse security log files
- Analyze IP address activity
- Detect failed login attempts
- Identify brute force attacks
- Detect directory scanning activity
- Reduce duplicate alerts with alert deduplication
- Assign severity levels (Low / Medium / High)
- Map detections to MITRE ATT&CK techniques
- Export security alerts into JSON reports

## Example Detection

### Brute Force Detection
🚨 Brute Force Attack
IP: 192.168.1.20
Attempts: 3
Severity: Low
MITRE ATT&CK:
T1110 - Brute Force

### Directory Scan Detection
🚨 Directory Scan
IP: 203.0.113.45
Target: /.env
Attempts: 1
Severity: High
MITRE ATT&CK:
T1595 - Active Scanning

## Screenshot

![SOC Log Analyzer Output](screenshots/soc-log-analyzer-output.png)


## Technologies

- Python 3
- Git
- macOS/Linux Terminal
- Cybersecurity log analysis concepts
- MITRE ATT&CK Framework


## Project Structure
soc-log-analyzer/
├── main.py
├── README.md
├── logs/
│ └── sample.log
├── reports/
│ └── security_alerts.json
└── screenshots/
└── soc-log-analyzer-output.png


## How to Run

Clone repository:
git clone <repository-url>

Run analyzer:
python3 main.py


## Future Improvements

- Add threat risk scoring
- Add IP reputation checks
- Add more MITRE ATT&CK techniques
- Create automated tests
- Add SIEM-style dashboard
- Improve false positive detection