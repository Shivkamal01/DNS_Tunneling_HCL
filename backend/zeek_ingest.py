import os
import psycopg2
from config import DB_CONFIG
from utils import calculate_entropy, evaluate_risk

# Zeek log path — override via ZEEK_LOG_PATH env variable or .env file
# Default falls back to <project_root>\zeek\logs\dns.log (cross-platform)
_base_dir = os.path.dirname(os.path.abspath(__file__))
_default_log = os.path.normpath(os.path.join(_base_dir, "..", "zeek", "logs", "dns.log"))
LOG_PATH = os.getenv("ZEEK_LOG_PATH", _default_log)

def parse_zeek_dns_log():
    if not os.path.exists(LOG_PATH):
        print(f"[!] Log file not found: {LOG_PATH}")
        return

    conn = psycopg2.connect(**DB_CONFIG)
    cursor = conn.cursor()

    fields = []
    processed_count = 0
    alert_count = 0

    print(f"[*] Ingesting Zeek telemetry from: {LOG_PATH}")

    with open(LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()

            # Parse Zeek header to dynamically map columns
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#") or not line or not fields:
                continue

            values = line.split("\t")
            record = dict(zip(fields, values))

            domain = record.get("query", "-")
            src_ip = record.get("id.orig_h", "0.0.0.0")
            
            # Skip empty or unassigned DNS requests
            if domain == "-" or not domain:
                continue

            # Parse query type and TTL safely
            qtype_raw = record.get("qtype", "1")
            qtype = int(qtype_raw) if qtype_raw.isdigit() else 1

            ttls_raw = record.get("TTLs", "0").split(",")[0]
            try:
                ttl = int(float(ttls_raw))
            except ValueError:
                ttl = 0

            # Feature extraction
            query_length = len(domain)
            labels = domain.split(".")
            subdomain = ".".join(labels[:-2]) if len(labels) > 2 else ""
            target_string = subdomain if subdomain else domain

            entropy = calculate_entropy(target_string)
            risk_score, severity, indicators = evaluate_risk(query_length, entropy)

            # 1. Insert into dns_queries
            cursor.execute("""
                INSERT INTO dns_queries (source_ip, domain, query_type, ttl)
                VALUES (%s, %s, %s, %s) RETURNING id;
            """, (src_ip, domain, qtype, ttl))
            query_id = cursor.fetchone()[0]

            # 2. Insert into dns_features
            cursor.execute("""
                INSERT INTO dns_features (query_id, query_length, entropy)
                VALUES (%s, %s, %s);
            """, (query_id, query_length, entropy))

            # 3. Create Alert if heuristic threshold is breached
            if risk_score > 0:
                reason = ", ".join(indicators)
                cursor.execute("""
                    INSERT INTO alerts (query_id, risk_score, severity, detection_reason, status)
                    VALUES (%s, %s, %s, %s, 'OPEN') RETURNING id;
                """, (query_id, risk_score, severity, reason))
                alert_id = cursor.fetchone()[0]
                alert_count += 1

                # 4. Escalate High/Critical severities to incidents
                if severity in ["High", "Critical"]:
                    cursor.execute("""
                        INSERT INTO incidents (alert_id, source_ip, domain, severity, status)
                        VALUES (%s, %s, %s, %s, 'INVESTIGATING');
                    """, (alert_id, src_ip, domain, severity))

            processed_count += 1

    conn.commit()
    cursor.close()
    conn.close()

    print(f"[+] Ingestion complete: {processed_count} DNS queries processed.")
    print(f"[+] Alerts generated: {alert_count}")

if __name__ == "__main__":
    parse_zeek_dns_log()
