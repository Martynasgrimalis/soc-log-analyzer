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