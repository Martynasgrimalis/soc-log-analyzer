from collections import Counter


def read_log_file(file_path):
    with open(file_path, "r") as file:
        logs = file.readlines()

    return logs


def extract_ips(logs):
    ips = []

    for log in logs:
        ip = log.split()[0]
        ips.append(ip)

    return ips


log_file = "logs/sample.log"

logs = read_log_file(log_file)

print("Number of log entries:", len(logs))

ips = extract_ips(logs)

ip_counter = Counter(ips)

print("\nIP Address Frequency")

for ip, count in ip_counter.items():
    print(ip, ":", count)