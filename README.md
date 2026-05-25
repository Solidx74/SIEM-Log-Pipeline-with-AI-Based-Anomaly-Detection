# 🛡️ SIEM Log Pipeline with AI-Based Anomaly Detection

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![Flask](https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?style=for-the-badge)]()

A production-ready Security Information and Event Management (SIEM) pipeline that collects, processes, and analyzes system logs in real-time using machine learning for anomaly detection.

---

## ✨ Features

- **Multi-Protocol Log Collection** — HTTP, TCP, UDP, and Syslog support
- **Real-Time Log Parsing** — Converts raw syslog/journald logs to structured JSON
- **Feature Engineering** — Extracts temporal, categorical, and textual features for ML
- **AI-Powered Anomaly Detection** — Isolation Forest, LOF, and One-Class SVM algorithms
- **Real-Time Monitoring** — Watchdog-based file monitoring with batch processing
- **Multi-Channel Alerting** — Console, webhook, file, and syslog alert outputs
- **Cross-Platform** — Works on Windows (mock logs) and Linux (real system logs)
- **Modular Architecture** — Easily extendable, loosely coupled components

---

## 📋 Table of Contents

- [Architecture](#-architecture)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Components](#-components)
- [Configuration](#-configuration)
- [Real Log Forwarding (Linux)](#-real-log-forwarding-linux)
- [Project Structure](#-project-structure)
- [License](#-license)
- [Contact](#-contact)

---

## 🏗️ Architecture

The pipeline follows a linear, stage-gated data flow:

```
[ Log Sources ]            HTTP / TCP / UDP / Syslog
       │
       ▼
[ log_collector.py ]       Receives and writes raw logs → raw_logs.log
       │
       ▼
[ log_parser.py ]          Parses raw lines into structured JSON → logs_parsed.json
       │
       ▼
[ features_extraction.py ] Enriches with temporal, service & message features → logs_features.jsonl
       │
       ▼
[ anomaly_detection.py ]   ML models flag anomalies → anomalies.jsonl
       │
       ▼
[ Alerting Channels ]      Console / Webhook / File / Syslog
```

---

## 📦 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### 1. Clone the repository

```bash
git clone https://github.com/Solidx74/SIEM-Log-Pipeline-with-AI-Based-Anomaly-Detection.git
cd SIEM-Log-Pipeline-with-AI-Based-Anomaly-Detection
```

### 2. Create and activate a virtual environment

```bash
# Linux / Mac
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
.\venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install flask watchdog scikit-learn pandas numpy requests
```

> **Linux only** — for real systemd log forwarding:
> ```bash
> pip install systemd-python
> ```

---

## 🚀 Quick Start

Run each stage of the pipeline in order:

```bash
# 1. Start the log collector
python log_collector.py --port 8080

# 2. Generate mock test logs (Windows / Mac)
python log_generator.py

# 3. Parse raw logs into structured JSON
python log_parser.py

# 4. Extract ML features
python features_extraction.py

# 5. Run anomaly detection
python anomaly_detection.py \
  --input logs/logs_features.jsonl \
  --algorithm isolation_forest \
  --output anomalies.jsonl \
  --alert-file alerts.jsonl
```

---

## 🧩 Components

### 1. `log_collector.py` — Log Ingestion Server

HTTP/TCP/UDP server that receives incoming logs and writes them to `raw_logs.log`.

```bash
# HTTP (default)
python log_collector.py --port 8080

# TCP
python log_collector.py --protocol tcp --port 8080

# UDP
python log_collector.py --protocol udp --port 8080
```

---

### 2. `log_generator.py` — Mock Log Generator *(Windows / Mac)*

Generates realistic syslog-style log entries for local testing. No configuration required.

```bash
python log_generator.py
```

---

### 3. `log_parser.py` — Structured Log Parser

Monitors `raw_logs.log` in real-time and converts each line into structured JSON.

**Output:** `logs/logs_parsed.json`

---

### 4. `features_extraction.py` — Feature Engineering

Enriches parsed log entries with ML-ready features:

| Feature Group | Examples |
|---|---|
| Temporal | Hour of day, day of week, weekend indicator |
| Message | Length, error/warning keyword presence |
| Service | Service name, system service classification |
| PID | Low / system / user PID range |

**Output:** `logs/logs_features.jsonl`

---

### 5. `anomaly_detection.py` — ML Anomaly Detector

Real-time anomaly detection engine supporting three algorithms:

- **Isolation Forest** *(default)* — best for high-dimensional sparse anomalies
- **Local Outlier Factor (LOF)** — density-based local anomaly scoring
- **One-Class SVM** — boundary-based novelty detection

Additional capabilities: real-time watchdog monitoring, configurable batch windows, model persistence (save/load), and multi-channel alerting.

---

## ⚙️ Configuration

All anomaly detection parameters are passed as CLI flags:

| Parameter | Default | Description |
|---|---|---|
| `--algorithm` | `isolation_forest` | Detection algorithm to use |
| `--contamination` | `0.1` | Expected proportion of anomalies in data |
| `--batch-size` | `100` | Number of log entries per processing batch |
| `--batch-timeout` | `10` | Seconds before flushing a partial batch |
| `--webhook-url` | `None` | HTTP endpoint to POST alerts |
| `--alert-file` | `None` | File path to write alert records |
| `--syslog` | `False` | Enable syslog alert output |
| `--output` | `None` | File path to write detected anomalies |
| `--save-model` | `None` | Path to persist the trained model |
| `--model-path` | `None` | Path to load a pre-trained model |

---

## 🐧 Real Log Forwarding (Linux)

Forward live systemd/journald logs to the pipeline using `log_forwarder.py`.

```bash
# Install Linux dependency
pip install systemd-python requests

# Forward via HTTP
python log_forwarder.py localhost 8080 --protocol http --batch-size 10

# Forward via TCP
python log_forwarder.py localhost 8080 --protocol tcp --batch-size 10

# Forward logs from a specific systemd unit (e.g. sshd)
python log_forwarder.py localhost 8080 --protocol http --unit sshd

# Forward via Syslog
python log_forwarder.py localhost 514 --protocol syslog
```

---

## 📁 Project Structure

```
├── log_collector.py         # Multi-protocol log ingestion server
├── log_generator.py         # Mock syslog generator for testing
├── log_parser.py            # Raw-to-JSON log parser
├── features_extraction.py   # ML feature engineering
├── anomaly_detection.py     # Real-time anomaly detection engine
├── log_forwarder.py         # Linux systemd log forwarder
├── logs/
│   ├── raw_logs.log         # Collected raw log lines
│   ├── logs_parsed.json     # Structured parsed logs
│   └── logs_features.jsonl  # Feature-enriched logs
├── requirements.txt         # Pinned dependencies
├── .gitignore
└── README.md
```

---

## 📜 License

Distributed under the [MIT License](LICENSE).

---

## 📬 Contact

**Kareeb Sadab**

[![X](https://img.shields.io/badge/X-@Solidx74-000000?style=flat&logo=x&logoColor=white)](https://x.com/Solidx74)
[![Gmail](https://img.shields.io/badge/Gmail-kareebsadab@gmail.com-D14836?style=flat&logo=gmail&logoColor=white)](mailto:kareebsadab@gmail.com)
[![GitHub](https://img.shields.io/badge/GitHub-Solidx74-181717?style=flat&logo=github&logoColor=white)](https://github.com/Solidx74)

---

<p align="center">Built with 🔐 by <a href="https://github.com/Solidx74">Solidx74</a></p>
