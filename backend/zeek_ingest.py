"""
Zeek dns.log ingestion.

Handles the tab-separated format Zeek writes, including the unset-field marker
("-"), the multi-value TTLs column, and the header block that declares column
order. Column positions are read from #fields rather than assumed, so the
importer keeps working across Zeek version changes.
"""

import argparse
import logging
import os
from datetime import datetime

import psycopg2

from config import DB_CONFIG
from ingest import ingest_record_safe, load_whitelist

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

_base_dir = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LOG = os.path.normpath(os.path.join(_base_dir, "..", "zeek", "logs", "dns.log"))
COMMIT_EVERY = 500

UNSET = "-"


def _first_ttl(raw: str) -> int:
    """Zeek records TTLs as a comma-separated vector; take the first sensible value."""
    if not raw or raw == UNSET:
        return 0
    for candidate in raw.split(","):
        try:
            return int(float(candidate))
        except (TypeError, ValueError):
            continue
    return 0


def parse_zeek_dns_log(log_path: str = None) -> dict:
    """Parse a Zeek dns.log and persist every query through the detection pipeline."""
    target = log_path or os.getenv("ZEEK_LOG_PATH") or DEFAULT_LOG

    if not os.path.exists(target):
        logger.error("Zeek log file not found: %s", target)
        return {"processed": 0, "inserted": 0, "alerts": 0, "incidents": 0,
                "skipped": 0, "failed": 0, "status": "file_not_found"}

    logger.info("Ingesting Zeek telemetry from: %s", target)

    conn = psycopg2.connect(**DB_CONFIG)
    cursor = conn.cursor()
    load_whitelist(cursor)

    fields = []
    processed = inserted = alerts = incidents = skipped = failed = 0

    try:
        with open(target, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                line = line.rstrip("\n")

                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                    continue
                if not line or line.startswith("#") or not fields:
                    continue

                record = dict(zip(fields, line.split("\t")))
                domain = record.get("query", UNSET).strip(".")
                if not domain or domain == UNSET:
                    continue

                source_ip = record.get("id.orig_h", "0.0.0.0")

                try:
                    timestamp = datetime.fromtimestamp(float(record.get("ts", "")))
                except (TypeError, ValueError):
                    timestamp = datetime.now()

                qtype_raw = record.get("qtype", "1")
                try:
                    qtype = int(qtype_raw)
                except (TypeError, ValueError):
                    qtype = 1
                if qtype == 41:  # EDNS0 OPT, not a query
                    continue

                qtype_name = record.get("qtype_name")
                if qtype_name in (None, UNSET):
                    qtype_name = None

                processed += 1
                try:
                    result = ingest_record_safe(
                        cursor,
                        domain=domain,
                        query_type=qtype,
                        source_ip=source_ip,
                        timestamp=timestamp,
                        ttl=_first_ttl(record.get("TTLs", UNSET)),
                        qtype_name=qtype_name,
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
                    # The savepoint keeps prior records; do not roll back the
                    # whole batch for one malformed line.
                    failed += 1
                    logger.warning("Skipped malformed record (%s): %s", line[:70], exc)

        conn.commit()

    finally:
        cursor.close()
        conn.close()

    logger.info("Zeek ingestion complete: %d records, %d inserted, %d duplicates skipped, %d failed",
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
    parser = argparse.ArgumentParser(description="Import queries from a Zeek dns.log file.")
    parser.add_argument("log", nargs="?", default=None, help="Path to dns.log (default: zeek/logs/dns.log)")
    args = parser.parse_args()
    parse_zeek_dns_log(args.log)
