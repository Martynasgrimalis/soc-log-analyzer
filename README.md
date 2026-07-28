# SOC Log Analyzer

A Python-based security log analysis tool designed to detect suspicious activity in application logs.

The project simulates a basic SOC analyst workflow:
- collecting log data
- analysing events
- detecting suspicious behaviour
- generating security alerts

## Features

- Parse security log files
- Count activity by source IP address
- Detect failed login attempts
- Identify possible brute force attacks
- Generate security alerts

## Example Detection

Example input:
192.168.1.20 POST /login 401
192.168.1.20 POST /login 401
192.168.1.20 POST /login 401

Generated alert:
Security Alert
Type: Brute Force Attack
IP: 192.168.1.20
Attempts: 3
Severity: Medium

## Technologies

- Python 3
- Git
- Linux/macOS terminal
- Cybersecurity log analysis concepts

## How to Run

Clone the repository:
git clone <repository-url>

Run the analyzer:
python3 main.py

## Project Structure
soc-log-analyzer/
├── main.py
├── README.md
└── logs/
└── sample.log

## Future Improvements

- Export alerts to JSON reports
- Add MITRE ATT&CK technique mapping
- Add IP reputation checks
- Improve false positive detection
- Add more advanced threat detection rules