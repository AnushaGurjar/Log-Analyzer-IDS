# 🛡️ Log File Analyzer for Intrusion Detection System

A Python-based Intrusion Detection System (IDS) tool that parses Apache access logs and SSH authentication logs to detect suspicious traffic, brute-force attempts, and unauthorized access patterns.

## 🌟 Key Features
- **Regex Parsing**: Automated extraction of IP addresses and security events.
- **Threat Detection Engine**: Identifies threshold-crossing brute-force attempts.
- **Data Visualization**: Graphs active IPs and request frequencies.
- **Incident Export**: Generates structured CSV threat reports for analysis.

## 📈 Visual Reports
- Graph Output: `Reports/ip_traffic_distribution.png`
- CSV Summary: `Reports/incident_report.csv`

## 🚀 Execution
```bash
pip install -r requirements.txt
python main.py
