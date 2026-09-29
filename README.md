# Incident Detection for DNS Tunneling Attack

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

## Future Roadmap: Phase 6 (Machine Learning)
While the heuristic engine excels at catching high-volume tunneling, sophisticated attackers occasionally use "low-and-slow" dictionary channels over several weeks. 
* **Next Steps:** Integration of **Scikit-Learn's Isolation Forest**.
* **Goal:** Run an unsupervised anomaly detection model in parallel with the heuristic engine to baseline "normal" network behavior and isolate microscopic, long-term frequency deviations.
