"""
PCAP ingestion: parse a capture file with Scapy and push every DNS query
through the shared detection pipeline.
"""

import argparse
import logging
import os
from datetime import datetime

import psycopg2
from scapy.all import PcapReader, DNS, DNSQR, IP, IPv6

from config import DB_CONFIG
from ingest import ingest_record_safe, load_whitelist

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

COMMIT_EVERY = 500  # commit in batches; per-packet commits dominated runtime

DEFAULT_PCAP = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "datasets", "suspicious", "test_traffic.pcap")
)


def analyze_pcap(pcap_path: str = None) -> dict:
    """
    Parse a PCAP, extract DNS telemetry, score it and persist the results.

    Returns a summary dict. Re-running on the same file is safe: duplicate
    queries are skipped by the unique index rather than inserted twice.
    """
    path = pcap_path or DEFAULT_PCAP

    if not os.path.exists(path):
        logger.error("PCAP file not found: %s", path)
        return {"processed": 0, "inserted": 0, "alerts": 0, "incidents": 0,
                "skipped": 0, "failed": 0, "status": "file_not_found"}

    logger.info("Analyzing PCAP capture: %s", path)

    conn = psycopg2.connect(**DB_CONFIG)
    cursor = conn.cursor()
    load_whitelist(cursor)

    processed = inserted = alerts = incidents = skipped = failed = 0

    try:
        with PcapReader(path) as packets:
            for pkt in packets:
                if not (
                    pkt.haslayer(DNS)
                    and pkt.haslayer(DNSQR)
                    and (pkt.haslayer(IP) or pkt.haslayer(IPv6))
                ):
                    continue
                # A capture contains both queries and responses. Only requests
                # belong in dns_queries; adding responses creates phantom
                # "queries" attributed to the resolver's IP address.
                if int(getattr(pkt[DNS], "qr", 0) or 0) != 0:
                    continue

                ip_layer = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
                processed += 1
                try:
                    qname = pkt[DNSQR].qname
                    if isinstance(qname, bytes):
                        qname = qname.decode("utf-8", errors="ignore")
                    domain = (qname or "").strip(".")
                    if not domain:
                        skipped += 1
                        continue

                    qtype = int(pkt[DNSQR].qtype)
                    if qtype == 41:  # EDNS0 OPT pseudo-record, not a real query
                        skipped += 1
                        continue

                    result = ingest_record_safe(
                        cursor,
                        domain=domain,
                        query_type=qtype,
                        source_ip=ip_layer.src,
                        timestamp=datetime.fromtimestamp(float(pkt.time)),
                    )

                    if result["inserted"]:
                        inserted += 1
                    else:
                        skipped += 1
                    if result["alert_id"]:
                        alerts += 1
                    if result["incident_id"]:
                        incidents += 1

                    if processed % COMMIT_EVERY == 0:
                        conn.commit()

                except Exception as exc:
                    # ingest_record_safe() rolled back only this record; keep
                    # every query already staged in the current transaction.
                    failed += 1
                    logger.warning("Error processing packet: %s", exc)

        conn.commit()

    finally:
        cursor.close()
        conn.close()

    logger.info("PCAP analysis complete: %d DNS query packets, %d inserted, %d skipped, %d failed",
                processed, inserted, skipped, failed)
    logger.info("Alerts generated: %d | Incidents escalated: %d", alerts, incidents)

    return {
        "processed": processed,
        "inserted": inserted,
        "skipped": skipped,
        "failed": failed,
        "alerts": alerts,
        "incidents": incidents,
        "status": "success",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Import DNS queries from a PCAP file.")
    parser.add_argument("pcap", nargs="?", default=None, help="Path to a .pcap file (default: bundled sample)")
    args = parser.parse_args()
    analyze_pcap(args.pcap)
