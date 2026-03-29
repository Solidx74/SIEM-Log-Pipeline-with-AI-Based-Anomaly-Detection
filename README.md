# SIEM Log Pipeline with AI-Based Anomaly Detection

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A production-ready Security Information and Event Management (SIEM) pipeline that collects, processes, and analyzes system logs in real-time using machine learning for anomaly detection.

##  Features

- **Multi-Protocol Log Collection**: HTTP, TCP, UDP, and Syslog support
- **Real-Time Log Parsing**: Converts raw syslog/journald logs to structured JSON
- **Feature Engineering**: Extracts temporal, categorical, and textual features for ML
- **AI-Powered Anomaly Detection**: Isolation Forest, LOF, and One-Class SVM algorithms
- **Real-Time Monitoring**: Watchdog-based file monitoring with batch processing
- **Multi-Channel Alerting**: Console, webhook, file, and syslog alerts
- **Cross-Platform**: Works on Windows (mock logs) and Linux (real system logs)
- **Modular Architecture**: Easily extendable components

##  Table of Contents

- [Architecture Overview](#architecture-overview)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Components](#components)
- [Usage Examples](#usage-examples)
- [Configuration](#configuration)
- [Real Log Forwarding (Linux)](#real-log-forwarding-linux)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

##  Architecture Overview

┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ Log Forwarder │────▶│ Log Collector │────▶│ Log Parser │
│ (systemd/journal│ │ (HTTP/TCP/UDP) │ │ (JSON Conversion)│
│ or Mock Gen) │ └─────────────────┘ └─────────────────┘
└─────────────────┘ │
▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ Alert Manager │◀────│Anomaly Detector │◀────│Feature Extractor│
│ (Webhook/File/ │ │ (ML Models) │ │ (Enrichment) │
│ Console) │ └─────────────────┘ └─────────────────┘
└─────────────────┘


## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Clone the Repository

git clone https://github.com/Solidx74/SIEM-Log-Pipeline-with-AI-Based-Anomaly-Detection.git
cd siem-log-pipeline


# Create Virtual Environment
bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate

# Install Dependencies

pip install flask watchdog scikit-learn pandas numpy requests

# For Linux with real log forwarding:

pip install systemd-python

🚀 Quick Start
1. Start the Log Collector

python log_collector.py --port 8080

2. Generate Test Logs (Windows/Mac)

python log_generator.py
3. Parse Logs

python log_parser.py

4. Extract Features

python features_extraction.py

5. Run Anomaly Detection

python anomaly_detection.py --input logs/logs_features.jsonl --algorithm isolation_forest --output anomalies.jsonl --alert-file alerts.jsonl


# Components
1. Log Collector (log_collector.py)
HTTP server that receives logs and writes them to raw log files.

Protocols: HTTP (default), TCP, UDP

Usage:

# HTTP (default)
python log_collector.py --port 8080

# TCP
python log_collector.py --protocol tcp --port 8080

# UDP
python log_collector.py --protocol udp --port 8080
2. Log Generator (log_generator.py) - Windows/Mac
Generates mock syslog-style logs for testing.

Usage:

python log_generator.py
3. Log Parser (log_parser.py)
Monitors raw log files and converts each line to structured JSON.

Output: logs/logs_parsed.json

4. Feature Extractor (features_extraction.py)
Enriches parsed logs with features:

Temporal: hour of day, day of week, weekend indicator

Message: length, error/warning keywords

Service: service name, system service classification

PID: low/system/user range

Output: logs/logs_features.jsonl

5. Anomaly Detector (anomaly_detection.py)
Real-time ML-based anomaly detection with:

Isolation Forest (default)

Local Outlier Factor (LOF)

One-Class SVM

Features:

Real-time file monitoring with watchdog

Batch processing with configurable windows

Model persistence (save/load)

Multi-channel alerting


# Installation (Linux)
1.
pip install systemd-python requests
2.Forward Logs via HTTP

python log_forwarder.py localhost 8080 --protocol http --batch-size 10
3.Forward Logs via TCP

python log_forwarder.py localhost 8080 --protocol tcp --batch-size 10
4.Forward Logs from Specific Systemd Unit

python log_forwarder.py localhost 8080 --protocol http --unit sshd
5.Forward Logs via Syslog

python log_forwarder.py localhost 514 --protocol syslog


# Project Structure
text
siem-log-pipeline/
├── logs/                          # Log storage directory
├── log_collector.py               # Log receiver server
├── log_generator.py               # Mock log generator (Windows/Mac)
├── log_forwarder.py               # Real log forwarder (Linux only)
├── log_parser.py                  # Raw log to JSON converter
├── features_extraction.py         # Feature engineering
├── anomaly_detection.py           # ML anomaly detection
├── requirements.txt               # Python dependencies
├── README.md                      # This file
└── .gitignore                     # Git ignore file


# Configuration
Anomaly Detection Parameters
Parameter	Default	Description
--algorithm	isolation_forest	Detection algorithm(s)
--contamination	0.1	Expected proportion of anomalies
--batch-size	100	Logs per batch
--batch-timeout	10	Seconds before processing partial batch
--webhook-url	None	Alert webhook endpoint
--alert-file	None	File to write alerts
--syslog	False	Enable syslog alerts
--output	None	File for detected anomalies
--save-model	None	Path to save trained model
--model-path	None	Path to load pre-trained model

# Pipeline Flow
Collection: Logs are received via HTTP/TCP/UDP and written to raw_logs.log

Parsing: Raw logs are parsed to structured JSON in logs_parsed.json

Feature Extraction: Features are extracted and saved to logs_features.jsonl

Detection: ML models analyze features and flag anomalies

Alerting: Anomalies trigger alerts to configured channels




📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

🙏 Acknowledgments
->scikit-learn for ML algorithms

->watchdog for file monitoring

->Flask for HTTP server

📧 Contact
Kareeb Sadab 
X: https://x.com/Solidx74 
Gmail: kareebsadab@gmail.com
