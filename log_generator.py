#!/usr/bin/env python3
"""
Generates mock syslog‑style logs and sends them to the collector.
"""

import requests
import time
import random
from datetime import datetime

def generate_syslog_line():
    programs = ['sshd', 'kernel', 'systemd', 'cron', 'sudo', 'httpd', 'mysql']
    messages = [
        'Connection closed by authenticating user',
        'Failed password for root',
        'Accepted password for user',
        'kernel: CPU soft lockup',
        'systemd: Started Session',
        'cron: (root) CMD (test)',
        'sudo: user : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/bin/bash',
        'httpd: GET /index.html 200',
        'mysql: Access denied for user',
        'warning: process taking too long',
        'ERROR: segmentation fault'  # Anomaly
    ]
    timestamp = datetime.now().strftime('%b %d %H:%M:%S')
    program = random.choice(programs)
    message = random.choice(messages)
    return f"{timestamp} localhost {program}: {message}"

def send_logs(count=100, interval=0.5):
    for i in range(count):
        log_line = generate_syslog_line()
        try:
            response = requests.post('http://localhost:8080/logs', data=log_line)
            if response.status_code == 200:
                print(f"Sent: {log_line}")
            else:
                print(f"Failed: {response.status_code}")
        except Exception as e:
            print(f"Error: {e}")
        time.sleep(interval)

if __name__ == '__main__':
    send_logs(50, 0.5)   # Send 50 logs, one every 0.5 sec