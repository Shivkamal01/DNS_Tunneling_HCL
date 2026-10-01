# Incident Detection for DNS Tunneling Attack

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![React](https://img.shields.io/badge/React-18-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green.svg)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-14+-blue.svg)


## Executive Summary
This project is an end-to-end cybersecurity pipeline designed to detect covert DNS tunneling—a technique used by Advanced Persistent Threats (APTs) to bypass firewalls and exfiltrate data. By mathematically analyzing network payloads rather than relying on static binary rules, this engine calculates the probability of malicious encoding in real-time.

## Architecture & Tech Stack
This system is built replicating a modern enterprise Security Operations Center (SOC) pipeline:
* **Network Telemetry:** Zeek / Scapy (Packet parsing & log generation)
* **Detection Engine:** Python (Mathematical entropy calculation & heuristic scoring)
* **Database / Persistence:** PostgreSQL (Normalized relational schema for threat intelligence)
* **Backend API:** FastAPI (RESTful JSON delivery)
* **Frontend SOC Dashboard:** React.js + Recharts (Live monitoring & incident response)

## Core Detection Logic
Attackers encode stolen data inside DNS subdomains (e.g., `a2b4c6d8.malicious.com`). To detect this programmatically without false positives, the detection engine utilizes:
1. **Shannon Entropy ($H(X)$):** Mathematically measures the randomness of the domain string. Encoded data yields a highly elevated entropy score compared to natural language domains.
2. **Feature Extraction:** Evaluates structural anomalies, including excessive query length (>45 chars) and label count.
3. **Dynamic Risk Scoring:** Aggregates penalty points to assign a 0–100 risk score, automatically classifying threats into Low, Medium, High, or Critical severities.

## Features
* **Real-time Log Ingestion:** Parses Zeek `dns.log` telemetry natively.
* **Database Logging:** Permanently stores parsed queries, extracted mathematical features, and generated alerts.
* **Interactive Triage:** Analysts can use the React dashboard to track incident lifecycles, transitioning alerts from `OPEN` to `INVESTIGATING` to `RESOLVED`.
* **Zero-False-Positive Focus:** Heuristic thresholds ensure analysts are only alerted to mathematically verified anomalies.

## Getting Started

### Prerequisites
- **Python 3.8+**
- **Node.js & npm**
- **PostgreSQL**

### Installation

1. **Database Setup**
   Ensure PostgreSQL is running. Create a database and user matching the credentials in `backend/.env.example`, then copy it to `.env` or rename it:
   ```bash
   cd backend
   cp .env.example .env
   ```
   *Update the `.env` file with your actual PostgreSQL credentials.*

2. **Backend Setup**
   Install Python dependencies and start the API:
   ```bash
   cd backend
   pip install -r requirements.txt
   python api.py
   ```

3. **Frontend Setup**
   Install Node modules and start the React dashboard:
   ```bash
   cd frontend
   npm install
   npm start
   ```

### Quick Start (Windows)
If you have Python and Node installed, you can simply run the provided PowerShell script from the root directory to start both the backend and frontend simultaneously:
```powershell
.\start_windows.ps1
```

## Future Roadmap: Phase 6 (Machine Learning)
While the heuristic engine excels at catching high-volume tunneling, sophisticated attackers occasionally use "low-and-slow" dictionary channels over several weeks. 
* **Next Steps:** Integration of **Scikit-Learn's Isolation Forest**.
* **Goal:** Run an unsupervised anomaly detection model in parallel with the heuristic engine to baseline "normal" network behavior and isolate microscopic, long-term frequency deviations.
