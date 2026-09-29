import math
import psycopg2
from scapy.all import PcapReader, DNS, DNSQR, IP

# Database configuration
DB_CONFIG = {
    "dbname": "dns_tunneling_db",
    "user": "db_user",
    "password": "securepassword123",
    "host": "localhost",
    "port": "5432"
}

def calculate_entropy(data):
    if not data: return 0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += - p_x * math.log2(p_x)
    return entropy

def evaluate_risk(query_length, entropy):
    score = 0
    indicators = []
    
    if query_length > 45:
        score += 15
        indicators.append("Long query")
    if entropy > 3.8:
        score += 20
        indicators.append("High entropy")
        
    if score <= 29: severity = "Low"
    elif score <= 59: severity = "Medium"
    elif score <= 79: severity = "High"
    else: severity = "Critical"
    
    return score, severity, indicators

def analyze_pcap(pcap_path):
    print("Connecting to database and analyzing traffic...")
    conn = psycopg2.connect(**DB_CONFIG)
    cursor = conn.cursor()
    
    with PcapReader(pcap_path) as packets:
        for pkt in packets:
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt.haslayer(IP):
                try:
                    src_ip = pkt[IP].src
                    ttl = pkt[IP].ttl
                    qtype = pkt[DNSQR].qtype
                    
                    qname_bytes = pkt[DNSQR].qname
                    domain = qname_bytes.decode('utf-8', errors='ignore').strip('.')
                    query_length = len(domain)
                    
                    labels = domain.split('.')
                    subdomain = '.'.join(labels[:-2]) if len(labels) > 2 else ""
                    target_string = subdomain if subdomain else domain
                    
                    entropy = calculate_entropy(target_string)
                    score, severity, indicators = evaluate_risk(query_length, entropy)
                    
                    # 1. Insert into dns_queries table
                    cursor.execute("""
                        INSERT INTO dns_queries (source_ip, domain, query_type, ttl)
                        VALUES (%s, %s, %s, %s) RETURNING id;
                    """, (src_ip, domain, qtype, ttl))
                    query_id = cursor.fetchone()[0]
                    
                    # 2. Insert into dns_features table
                    cursor.execute("""
                        INSERT INTO dns_features (query_id, query_length, entropy)
                        VALUES (%s, %s, %s);
                    """, (query_id, query_length, entropy))
                    
                    # 3. If suspicious, insert into alerts table
                    if score > 0:
                        reason = ", ".join(indicators)
                        cursor.execute("""
                            INSERT INTO alerts (query_id, risk_score, severity, detection_reason)
                            VALUES (%s, %s, %s, %s) RETURNING id;
                        """, (query_id, score, severity, reason))
                        alert_id = cursor.fetchone()[0]
                        
                        # 4. If High or Critical, automatically open an incident
                        if severity in ["High", "Critical"]:
                            cursor.execute("""
                                INSERT INTO incidents (alert_id, source_ip, domain, severity)
                                VALUES (%s, %s, %s, %s);
                            """, (alert_id, src_ip, domain, severity))
                            
                    conn.commit()
                except Exception as e:
                    conn.rollback()
                    continue
                    
    cursor.close()
    conn.close()
    print("Analysis complete. Threats and traffic saved to PostgreSQL!")

if __name__ == "__main__":
    analyze_pcap("../datasets/suspicious/test_traffic.pcap")
