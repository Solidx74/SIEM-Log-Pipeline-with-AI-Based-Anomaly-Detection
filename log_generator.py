#!/usr/bin/env python3
"""
Continuous mock log generator for real-time testing
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
        'ERROR: segmentation fault',  # Anomaly
        'Failed password for invalid user',
        'Connection refused',
        'Timeout error occurred'
    ]
    timestamp = datetime.now().strftime('%b %d %H:%M:%S')
    program = random.choice(programs)
    message = random.choice(messages)
    return f"{timestamp} localhost {program}: {message}"

def send_logs_continuously(batch_size=10, interval=0.5, pause=5):
    """Send logs in batches continuously"""
    print(f"Starting continuous log generation...")
    print(f"Batch size: {batch_size} logs, Interval: {interval}s, Pause between batches: {pause}s")
    print("Press Ctrl+C to stop\n")
    
    batch_count = 0
    try:
        while True:
            batch_count += 1
            print(f"\n📤 Sending batch #{batch_count}...")
            
            for i in range(batch_size):
                log_line = generate_syslog_line()
                try:
                    response = requests.post('http://localhost:8080/logs', data=log_line, timeout=2)
                    if response.status_code == 200:
                        print(f"  ✓ {log_line[:80]}...")
                    else:
                        print(f"  ✗ Failed: {response.status_code}")
                except Exception as e:
                    print(f"  ✗ Error: {e}")
                time.sleep(interval)
            
            print(f"✅ Batch #{batch_count} completed. Waiting {pause} seconds...")
            time.sleep(pause)
            
    except KeyboardInterrupt:
        print(f"\n\n🛑 Stopped after {batch_count} batches")

if __name__ == '__main__':
    # Customize these parameters
    send_logs_continuously(
        batch_size=10,    # Logs per batch
        interval=0.3,     # Seconds between each log
        pause=5           # Seconds between batches
    )