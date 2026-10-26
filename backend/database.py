"""
Schema definition and migration for the DNS tunneling detection platform.

Run directly to create or migrate tables:  python database.py
"""

import logging
import sys

import psycopg2

from config import DB_CONFIG

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

INITIAL_WHITELIST = [
    ("google.com", "Core Google search and infrastructure services"),
    ("google-analytics.com", "Google telemetry & web analytics"),
    ("googleapis.com", "Google API endpoints"),
    ("gstatic.com", "Google static content CDN"),
    ("1e100.net", "Google internal network backbone"),
    ("akamaiedge.net", "Akamai Edge distribution network"),
    ("akamai.net", "Akamai DNS infrastructure"),
    ("cloudfront.net", "Amazon CloudFront content delivery"),
    ("azure.com", "Microsoft Azure cloud services"),
    ("windowsupdate.com", "Microsoft Windows Update telemetry"),
    ("microsoft.com", "Microsoft enterprise ecosystem"),
    ("office365.com", "Microsoft 365 service endpoints"),
    ("apple.com", "Apple device services"),
    ("icloud.com", "Apple iCloud services"),
    ("github.com", "GitHub infrastructure"),
    ("cloudflare.com", "Cloudflare DNS & proxy"),
    ("amazonaws.com", "AWS service endpoints"),
    ("in-addr.arpa", "Reverse DNS lookup namespace"),
    ("ip6.arpa", "IPv6 reverse DNS namespace"),
]

DDL = [
    """
    CREATE TABLE IF NOT EXISTS dns_queries (
        id SERIAL PRIMARY KEY,
        timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        source_ip VARCHAR(50),
        domain VARCHAR(255) NOT NULL,
        query_type INT,
        ttl INT,
        qtype_name VARCHAR(10) DEFAULT 'A'
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS dns_features (
        id SERIAL PRIMARY KEY,
        query_id INT REFERENCES dns_queries(id) ON DELETE CASCADE,
        query_length INT,
        entropy FLOAT,
        entropy_ratio FLOAT DEFAULT 0.0,
        subdomain_length INT DEFAULT 0,
        label_count INT DEFAULT 2,
        max_label_length INT DEFAULT 0,
        digit_ratio FLOAT DEFAULT 0.0,
        hex_ratio FLOAT DEFAULT 0.0,
        base32_foreign_ratio FLOAT,
        vowel_ratio FLOAT DEFAULT 0.0,
        consonant_run INT DEFAULT 0,
        est_payload_bytes INT DEFAULT 0,
        encoding VARCHAR(10) DEFAULT 'ascii',
        is_whitelisted BOOLEAN DEFAULT FALSE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS alerts (
        id SERIAL PRIMARY KEY,
        query_id INT REFERENCES dns_queries(id) ON DELETE CASCADE,
        risk_score INT,
        severity VARCHAR(20),
        detection_reason TEXT,
        indicators TEXT DEFAULT '',
        analyst_notes TEXT DEFAULT '',
        status VARCHAR(20) DEFAULT 'OPEN',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS incidents (
        id SERIAL PRIMARY KEY,
        alert_id INT REFERENCES alerts(id) ON DELETE CASCADE,
        source_ip VARCHAR(50),
        domain VARCHAR(255),
        severity VARCHAR(20),
        status VARCHAR(20) DEFAULT 'OPEN',
        assigned_to VARCHAR(100) DEFAULT 'Unassigned',
        analyst_notes TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS whitelist (
        id SERIAL PRIMARY KEY,
        domain_pattern VARCHAR(255) UNIQUE NOT NULL,
        reason TEXT,
        added_by VARCHAR(50) DEFAULT 'admin',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
]

# Applied after DDL so an existing database from an earlier version is upgraded
# in place rather than requiring a rebuild.
MIGRATIONS = [
    "ALTER TABLE dns_features ADD COLUMN IF NOT EXISTS entropy_ratio FLOAT DEFAULT 0.0;",
    "ALTER TABLE dns_features ADD COLUMN IF NOT EXISTS base32_foreign_ratio FLOAT;",
    "ALTER TABLE dns_features ADD COLUMN IF NOT EXISTS consonant_run INT DEFAULT 0;",
    "ALTER TABLE dns_features ADD COLUMN IF NOT EXISTS encoding VARCHAR(10) DEFAULT 'ascii';",
    "ALTER TABLE dns_features ADD COLUMN IF NOT EXISTS is_whitelisted BOOLEAN DEFAULT FALSE;",
    "ALTER TABLE dns_queries ALTER COLUMN timestamp SET NOT NULL;",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS indicators TEXT DEFAULT '';",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS analyst_notes TEXT DEFAULT '';",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;",
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS assigned_to VARCHAR(100) DEFAULT 'Unassigned';",
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS analyst_notes TEXT DEFAULT '';",
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;",
    "ALTER TABLE incidents ALTER COLUMN status SET DEFAULT 'OPEN';",
    # Drop the old column whose name advertised a measure it did not compute.
    # base32_ratio was ~1.0 for every lowercase hostname; see utils.py.
    "ALTER TABLE dns_features DROP COLUMN IF EXISTS base32_ratio;",
]

# De-duplicate before adding the constraint, otherwise the index creation fails
# on databases populated by the old (non-idempotent) importers.
DEDUPE_SQL = """
DELETE FROM dns_queries q
USING dns_queries keep
WHERE q.id > keep.id
  AND q.timestamp = keep.timestamp
  AND q.source_ip = keep.source_ip
  AND q.domain = keep.domain
  AND q.query_type = keep.query_type;
"""

UNIQUE_INDEX_SQL = """
CREATE UNIQUE INDEX IF NOT EXISTS ux_dns_queries_dedupe
ON dns_queries (timestamp, source_ip, domain, query_type);
"""

INDEXES = [
    "CREATE INDEX IF NOT EXISTS ix_dns_queries_timestamp ON dns_queries (timestamp DESC);",
    "CREATE INDEX IF NOT EXISTS ix_dns_queries_domain ON dns_queries (domain);",
    "CREATE INDEX IF NOT EXISTS ix_alerts_created_at ON alerts (created_at DESC);",
    "CREATE INDEX IF NOT EXISTS ix_alerts_severity ON alerts (severity);",
    "CREATE INDEX IF NOT EXISTS ix_alerts_status ON alerts (status);",
    "CREATE INDEX IF NOT EXISTS ix_alerts_query_id ON alerts (query_id);",
    "CREATE INDEX IF NOT EXISTS ix_incidents_alert_id ON incidents (alert_id);",
    "CREATE INDEX IF NOT EXISTS ix_incidents_status ON incidents (status);",
    "CREATE INDEX IF NOT EXISTS ix_dns_features_query_id ON dns_features (query_id);",
]


def _apply_step(conn, cursor, statement: str, label: str) -> bool:
    """
    Run one optional DDL step inside a savepoint.

    A failed statement aborts the whole PostgreSQL transaction. The previous
    implementation called conn.rollback() here, which silently discarded every
    DDL statement and migration that had already succeeded in the same run.
    A savepoint confines the failure to the step that caused it.
    """
    cursor.execute("SAVEPOINT schema_step;")
    try:
        cursor.execute(statement)
        cursor.execute("RELEASE SAVEPOINT schema_step;")
        return True
    except Exception as exc:
        cursor.execute("ROLLBACK TO SAVEPOINT schema_step;")
        cursor.execute("RELEASE SAVEPOINT schema_step;")
        logger.warning("%s skipped (%s): %s", label, exc.__class__.__name__, str(exc).strip()[:120])
        return False


def init_db() -> bool:
    """Create or migrate every table. Returns True on success."""
    conn = None
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        conn.autocommit = False
        cursor = conn.cursor()

        # Seed the default rules only on a genuine first run. Re-seeding an
        # existing but empty table would resurrect rules an analyst deliberately
        # deleted on the next start, defeating the database-backed whitelist.
        cursor.execute("SELECT to_regclass('whitelist') IS NOT NULL;")
        whitelist_existed = cursor.fetchone()[0]

        # Required table creation is not optional: fail fast with a useful log.
        for index, statement in enumerate(DDL, start=1):
            try:
                cursor.execute(statement)
            except Exception:
                logger.exception("Required schema statement %d failed", index)
                conn.rollback()
                return False

        for statement in MIGRATIONS:
            _apply_step(conn, cursor, statement, "Migration")

        _apply_step(
            conn,
            cursor,
            f"{DEDUPE_SQL}\n{UNIQUE_INDEX_SQL}",
            "Query de-duplication index",
        )

        for statement in INDEXES:
            _apply_step(conn, cursor, statement, "Index")

        if not whitelist_existed:
            for pattern, reason in INITIAL_WHITELIST:
                cursor.execute(
                    """
                    INSERT INTO whitelist (domain_pattern, reason, added_by)
                    VALUES (%s, %s, 'system')
                    ON CONFLICT (domain_pattern) DO NOTHING;
                    """,
                    (pattern, reason),
                )

        conn.commit()
        cursor.close()
        logger.info("Database schema initialized and verified.")
        return True

    except Exception as exc:
        if conn is not None:
            conn.rollback()
        logger.error("Error connecting to database: %s", exc)
        return False
    finally:
        if conn is not None:
            conn.close()


if __name__ == "__main__":
    sys.exit(0 if init_db() else 1)
