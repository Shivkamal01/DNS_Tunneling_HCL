"""
Single ingestion path shared by every telemetry source.

Previously the query -> features -> alert -> incident sequence was duplicated
verbatim in main.py, zeek_ingest.py and api.py. Any change to scoring or
escalation had to be applied three times, and analyst whitelist rules could not
be honoured consistently because each copy had its own idea of what to insert.
All three sources now call ingest_record().
"""

import logging
from datetime import datetime
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

ESCALATE_SEVERITIES = ("High", "Critical")


def load_whitelist(cursor) -> None:
    """
    Pull analyst-managed rules from the database into the scoring engine.

    utils keeps a module-level cache because evaluate_risk() is called in tight
    loops; refreshing it here (at startup and after every whitelist write) keeps
    the cache authoritative without a query per packet.
    """
    from utils import set_whitelist

    try:
        cursor.execute("SELECT domain_pattern FROM whitelist;")
        patterns = [row[0] for row in cursor.fetchall()]
        set_whitelist(patterns)
        logger.info("Loaded %d whitelist rules into the detection engine", len(patterns))
    except Exception as exc:  # table may not exist yet on first run
        logger.warning("Could not load whitelist rules: %s", exc)


def ingest_record(
    cursor,
    domain: str,
    query_type: int,
    source_ip: str,
    timestamp: Optional[datetime] = None,
    ttl: int = 0,
    qtype_name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Persist one DNS query and everything derived from it.

    Returns a summary dict: {"inserted": bool, "alert_id": int|None,
    "severity": str|None, "incident_id": int|None}. A duplicate query (same
    timestamp, source, name and type — i.e. the same capture ingested twice)
    is skipped rather than inserted again, so re-running an import is safe.
    """
    from utils import extract_dns_features, evaluate_risk, RECORD_TYPES

    ts = timestamp or datetime.now()
    features = extract_dns_features(domain, query_type)
    qtype = qtype_name or RECORD_TYPES.get(query_type, f"TYPE_{query_type}")

    # The unique index on (timestamp, source_ip, domain, query_type) makes this
    # idempotent: a second pass over the same log file inserts nothing.
    cursor.execute(
        """
        INSERT INTO dns_queries (timestamp, source_ip, domain, query_type, ttl, qtype_name)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (timestamp, source_ip, domain, query_type) DO NOTHING
        RETURNING id;
        """,
        (ts, source_ip, features["domain"], query_type, ttl, qtype),
    )
    row = cursor.fetchone()
    if row is None:
        return {"inserted": False, "alert_id": None, "severity": None, "incident_id": None}

    query_id = row[0]

    cursor.execute(
        """
        INSERT INTO dns_features (
            query_id, query_length, entropy, entropy_ratio, subdomain_length,
            label_count, max_label_length, digit_ratio, hex_ratio,
            base32_foreign_ratio, vowel_ratio, consonant_run,
            est_payload_bytes, encoding, is_whitelisted
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
        """,
        (
            query_id,
            features["query_length"],
            features["entropy"],
            features["entropy_ratio"],
            features["subdomain_length"],
            features["label_count"],
            features["max_label_length"],
            features["digit_ratio"],
            features["hex_ratio"],
            features["base32_foreign_ratio"],
            features["vowel_ratio"],
            features["consonant_run"],
            features["est_payload_bytes"],
            features["encoding"],
            features["is_whitelisted"],
        ),
    )

    score, severity, indicators = evaluate_risk(features)

    # Score 0 means "nothing above threshold" — recording it as an alert would
    # bury the table in benign rows.
    if score <= 0:
        return {"inserted": True, "alert_id": None, "severity": severity, "incident_id": None}

    reason = indicators[0] if indicators else "Elevated risk heuristic"
    cursor.execute(
        """
        INSERT INTO alerts (
            query_id, risk_score, severity, detection_reason,
            indicators, status, created_at, updated_at
        )
        VALUES (%s, %s, %s, %s, %s, 'OPEN', %s, %s) RETURNING id;
        """,
        (query_id, score, severity, reason, " | ".join(indicators), ts, ts),
    )
    alert_id = cursor.fetchone()[0]

    incident_id = None
    if severity in ESCALATE_SEVERITIES:
        cursor.execute(
            """
            INSERT INTO incidents (
                alert_id, source_ip, domain, severity, status,
                assigned_to, analyst_notes, created_at, updated_at
            )
            VALUES (%s, %s, %s, %s, 'INVESTIGATING', 'Unassigned',
                    'Auto-escalated from detection engine', %s, %s) RETURNING id;
            """,
            (alert_id, source_ip, features["domain"], severity, ts, ts),
        )
        incident_id = cursor.fetchone()[0]

    return {
        "inserted": True,
        "alert_id": alert_id,
        "severity": severity,
        "incident_id": incident_id,
        "score": score,
    }
