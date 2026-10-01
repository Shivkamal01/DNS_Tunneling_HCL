import os
import psycopg2
from scapy.all import PcapReader, DNS, DNSQR, IP
from config import DB_CONFIG
from utils import calculate_entropy, evaluate_risk

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
                            INSERT INTO alerts (query_id, risk_score, severity, detection_reason, status)
                            VALUES (%s, %s, %s, %s, 'OPEN') RETURNING id;
                        """, (query_id, score, severity, reason))
                        alert_id = cursor.fetchone()[0]
                        
                        # 4. If High or Critical, automatically open an incident
                        if severity in ["High", "Critical"]:
                            cursor.execute("""
                                INSERT INTO incidents (alert_id, source_ip, domain, severity, status)
                                VALUES (%s, %s, %s, %s, 'INVESTIGATING');
                            """, (alert_id, src_ip, domain, severity))
                            
                    conn.commit()
                except Exception as e:
                    conn.rollback()
                    print(f"[!] Error processing packet: {e}")
                    continue
                    
    cursor.close()
    conn.close()
    print("Analysis complete. Threats and traffic saved to PostgreSQL!")

if __name__ == "__main__":
    # Resolve path relative to this script's location, works on both Linux and Windows
    base_dir = os.path.dirname(os.path.abspath(__file__))
    pcap_path = os.path.join(base_dir, "..", "datasets", "suspicious", "test_traffic.pcap")
    analyze_pcap(os.path.normpath(pcap_path))
