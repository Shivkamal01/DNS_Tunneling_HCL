"""
REST API for the DNS tunneling detection platform.

Error handling contract: every endpoint returns a meaningful HTTP status code
and an {"error": {"message": ..., "detail": ...}} body on failure. The previous
version returned HTTP 200 with {"status": "error"} for database failures, which
made 404s indistinguishable from outages in the dashboard.
"""

import csv
import io
import logging
import os
import random
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, List, Literal, Optional

import psycopg2
import uvicorn
from fastapi import FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from psycopg2.extras import RealDictCursor
from pydantic import BaseModel, Field, field_validator
from starlette.exceptions import HTTPException as StarletteHTTPException

from config import DB_CONFIG
from ingest import ingest_record_safe, load_whitelist
from utils import extract_dns_features, evaluate_risk
from zeek_ingest import parse_zeek_dns_log

# Scapy is imported lazily inside trigger_pcap_ingest() so the API still starts
# on a machine where the optional PCAP dependency is missing — only that one
# endpoint degrades.

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


# ─── Application lifecycle ───────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load analyst whitelist rules into the scoring engine before serving."""
    conn = None
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        load_whitelist(cursor)
        cursor.close()
    except Exception as exc:
        logger.warning("Could not preload whitelist (%s) — using built-in defaults", exc)
    finally:
        if conn is not None:
            conn.close()
    yield


app = FastAPI(
    title="DNS Tunneling Detection & Threat Intelligence Platform",
    description=(
        "SOC pipeline for covert DNS tunneling detection: entropy analysis, "
        "lexical feature extraction, risk scoring and incident triage."
    ),
    version="2.1.0",
    lifespan=lifespan,
)

ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000"
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

ALERT_STATUSES = ("OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE POSITIVE")
INCIDENT_STATUSES = ALERT_STATUSES + ("CLOSED",)
APP_STARTED_AT = datetime.now(timezone.utc)


# ─── Health ─────────────────────────────────────────────────────────────────
@app.get("/api/health")
def health():
    """Cheap liveness check the dashboard can use without pulling telemetry."""
    with db_cursor() as (conn, cursor):
        cursor.execute("SELECT 1 AS ok;")
        cursor.fetchone()
    return {
        "status": "ok",
        "database": "connected",
        "version": app.version,
        "started_at": APP_STARTED_AT.isoformat().replace("+00:00", "Z"),
        "server_time": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


# ─── Infrastructure helpers ─────────────────────────────────────────────────
class ApiError(Exception):
    """Raised for conditions that should surface as a non-200 response."""

    def __init__(self, status_code: int, message: str, detail: str = ""):
        self.status_code = status_code
        self.message = message
        self.detail = detail


@app.exception_handler(ApiError)
async def api_error_handler(request: Request, exc: ApiError):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"message": exc.message, "detail": exc.detail}},
    )


@app.exception_handler(psycopg2.Error)
async def db_error_handler(request: Request, exc: psycopg2.Error):
    logger.error("Database error on %s: %s", request.url.path, exc)
    return JSONResponse(
        status_code=503,
        content={"error": {"message": "Database unavailable", "detail": str(exc).strip()}},
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    """Keep validation failures in the same envelope as every other route."""
    first = exc.errors()[0] if exc.errors() else {}
    location = ".".join(
        str(part) for part in first.get("loc", ()) if part not in ("body", "query", "path")
    )
    message = first.get("msg", "Request validation failed")
    detail = f"{location}: {message}" if location else message
    return JSONResponse(
        status_code=422,
        content={"error": {"message": "Validation failed", "detail": detail}},
    )


@app.exception_handler(StarletteHTTPException)
async def http_error_handler(request: Request, exc: StarletteHTTPException):
    message = exc.detail if isinstance(exc.detail, str) else "Request failed"
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"message": message, "detail": ""}},
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception):
    """Log the traceback server-side but never leak internals to the client."""
    logger.exception("Unhandled error on %s", request.url.path)
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "message": "Internal server error",
                "detail": "The request could not be completed.",
            }
        },
    )


@contextmanager
def db_cursor(dict_rows: bool = True):
    """
    Transaction-scoped cursor. Commits on clean exit, rolls back on error.

    Synchronous on purpose: every endpoint here is a plain def, so FastAPI runs
    it in a worker thread and a blocking DB call is correct. An async context
    manager would require `async with` and cannot be used from these functions.
    """
    conn = psycopg2.connect(**DB_CONFIG)
    cursor = conn.cursor(cursor_factory=RealDictCursor) if dict_rows else conn.cursor()
    try:
        yield conn, cursor
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()


def serialize_dates(value):
    """Recursively convert datetime values to unambiguous ISO-8601 strings.

    PostgreSQL columns in this project are naive TIMESTAMP values written from
    the server's local clock. Attaching the local offset before converting to
    UTC means a browser in another timezone still renders the correct instant;
    without it, JavaScript would interpret the naive string as its own local
    time and silently shift the alert history.
    """
    if isinstance(value, list):
        return [serialize_dates(item) for item in value]
    if isinstance(value, dict):
        return {key: serialize_dates(item) for key, item in value.items()}
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.astimezone()
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return value


def split_indicators(raw: Optional[str]) -> List[str]:
    return [part.strip() for part in (raw or "").split("|") if part.strip()]


# ─── Request models ─────────────────────────────────────────────────────────
class StatusUpdate(BaseModel):
    status: str
    analyst_notes: Optional[str] = Field(default=None, max_length=4000)

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str) -> str:
        normalized = value.strip().upper()
        if normalized not in ALERT_STATUSES:
            raise ValueError(f"status must be one of {', '.join(ALERT_STATUSES)}")
        return normalized


class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = Field(default=None, max_length=100)
    analyst_notes: Optional[str] = Field(default=None, max_length=4000)

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip().upper()
        if normalized not in INCIDENT_STATUSES:
            raise ValueError(f"status must be one of {', '.join(INCIDENT_STATUSES)}")
        return normalized


class WhitelistCreate(BaseModel):
    domain_pattern: str = Field(min_length=3, max_length=255)
    reason: Optional[str] = Field(default="Manual analyst whitelist rule", max_length=500)

    @field_validator("domain_pattern")
    @classmethod
    def validate_domain(cls, value: str) -> str:
        cleaned = value.strip().strip(".").lower()
        if "." not in cleaned:
            raise ValueError("domain_pattern must contain at least one dot")
        if "*" in cleaned:
            raise ValueError(
                "Wildcards are not supported; add a concrete domain suffix instead"
            )
        if ".." in cleaned:
            raise ValueError("domain_pattern contains an empty label")
        if not all(c.isalnum() or c in ".-_" for c in cleaned):
            raise ValueError("domain_pattern contains invalid characters")
        return cleaned


class SimulationRequest(BaseModel):
    scenario: Literal["all", "base32_exfil", "c2_beaconing", "iodine_hex", "benign"] = "all"
    count: int = Field(default=5, ge=1, le=50)


# ─── Alerts ─────────────────────────────────────────────────────────────────
@app.get("/api/alerts")
def list_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    with db_cursor() as (conn, cursor):
        where = ["1=1"]
        params: List[Any] = []

        if severity and severity.upper() != "ALL":
            where.append("UPPER(a.severity) = %s")
            params.append(severity.upper())

        if status and status.upper() != "ALL":
            where.append("UPPER(a.status) = %s")
            params.append(status.upper())

        if search:
            where.append(
                "(q.domain ILIKE %s OR q.source_ip ILIKE %s "
                "OR a.detection_reason ILIKE %s OR a.indicators ILIKE %s)"
            )
            wildcard = f"%{search}%"
            params.extend([wildcard] * 4)

        clause = " AND ".join(where)

        # Total for the current filter, so the UI can show "showing 100 of 214"
        cursor.execute(
            f"""
            SELECT count(*) AS total
            FROM alerts a
            JOIN dns_queries q ON a.query_id = q.id
            WHERE {clause};
            """,
            tuple(params),
        )
        total = cursor.fetchone()["total"]

        cursor.execute(
            f"""
            SELECT
                a.id, a.query_id, a.risk_score, a.severity, a.detection_reason,
                a.indicators, a.analyst_notes, a.status, a.created_at, a.updated_at,
                q.domain, q.source_ip, q.query_type,
                COALESCE(q.qtype_name, 'A') AS qtype_name, q.ttl,
                f.query_length, f.entropy, f.entropy_ratio,
                COALESCE(f.subdomain_length, 0) AS subdomain_length,
                COALESCE(f.label_count, 2) AS label_count,
                COALESCE(f.max_label_length, 0) AS max_label_length,
                COALESCE(f.digit_ratio, 0.0) AS digit_ratio,
                COALESCE(f.hex_ratio, 0.0) AS hex_ratio,
                COALESCE(f.base32_foreign_ratio, 1.0) AS base32_foreign_ratio,
                COALESCE(f.vowel_ratio, 0.0) AS vowel_ratio,
                COALESCE(f.est_payload_bytes, 0) AS est_payload_bytes,
                COALESCE(f.encoding, 'ascii') AS encoding
            FROM alerts a
            JOIN dns_queries q ON a.query_id = q.id
            LEFT JOIN dns_features f ON a.query_id = f.query_id
            WHERE {clause}
            ORDER BY a.created_at DESC, a.risk_score DESC
            LIMIT %s OFFSET %s;
            """,
            tuple(params + [limit, offset]),
        )
        rows = cursor.fetchall()

        for row in rows:
            row["indicator_list"] = split_indicators(row.get("indicators"))

        return {
            "status": "success",
            "count": len(rows),
            "total": total,
            "limit": limit,
            "offset": offset,
            "data": serialize_dates(rows),
        }


@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: int):
    with db_cursor() as (conn, cursor):
        cursor.execute(
            """
            SELECT a.*,
                   q.domain, q.source_ip, q.query_type, q.qtype_name, q.ttl,
                   q.timestamp AS query_time,
                   f.query_length, f.entropy, f.entropy_ratio, f.subdomain_length,
                   f.label_count, f.max_label_length, f.digit_ratio, f.hex_ratio,
                   f.base32_foreign_ratio, f.vowel_ratio, f.consonant_run,
                   f.est_payload_bytes, f.encoding, f.is_whitelisted
            FROM alerts a
            JOIN dns_queries q ON a.query_id = q.id
            LEFT JOIN dns_features f ON a.query_id = f.query_id
            WHERE a.id = %s;
            """,
            (alert_id,),
        )
        alert = cursor.fetchone()

        if alert is None:
            raise ApiError(404, "Alert not found", f"No alert with id {alert_id}")

        alert["indicator_list"] = split_indicators(alert.get("indicators"))

        cursor.execute(
            "SELECT id, status, assigned_to, analyst_notes, created_at "
            "FROM incidents WHERE alert_id = %s ORDER BY id DESC;",
            (alert_id,),
        )
        alert["incidents"] = cursor.fetchall()

        return {"status": "success", "data": serialize_dates(alert)}


@app.put("/api/alerts/{alert_id}/status")
def update_alert_status(alert_id: int, update: StatusUpdate):
    with db_cursor(dict_rows=False) as (conn, cursor):
        cursor.execute(
            """
            UPDATE alerts
               SET status = %s,
                   analyst_notes = COALESCE(%s, analyst_notes),
                   updated_at = CURRENT_TIMESTAMP
             WHERE id = %s
            RETURNING id;
            """,
            (update.status, update.analyst_notes, alert_id),
        )
        if cursor.fetchone() is None:
            raise ApiError(404, "Alert not found", f"No alert with id {alert_id}")

        # Keep the linked incident lifecycle in step with its alert, but never
        # reopen a case that has already been closed out. Resolving or marking
        # an alert as a false positive must propagate; reopening a terminal
        # incident because an analyst re-read the alert must not.
        cursor.execute(
            """
            UPDATE incidents
               SET status = %s,
                   updated_at = CURRENT_TIMESTAMP
             WHERE alert_id = %s
               AND NOT (
                   UPPER(status) IN ('RESOLVED', 'CLOSED', 'FALSE POSITIVE')
                   AND %s NOT IN ('RESOLVED', 'CLOSED', 'FALSE POSITIVE')
               );
            """,
            (update.status, alert_id, update.status),
        )

        return {
            "status": "success",
            "message": f"Alert #{alert_id} marked {update.status}",
            "data": {"id": alert_id, "status": update.status},
        }


# ─── Incidents ──────────────────────────────────────────────────────────────
@app.get("/api/incidents")
def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(200, ge=1, le=500),
):
    with db_cursor() as (conn, cursor):
        where = ["1=1"]
        params: List[Any] = []

        if status and status.upper() != "ALL":
            where.append("UPPER(i.status) = %s")
            params.append(status.upper())
        if severity and severity.upper() != "ALL":
            where.append("UPPER(i.severity) = %s")
            params.append(severity.upper())

        cursor.execute(
            f"""
            SELECT i.*, a.risk_score, a.detection_reason, a.query_id,
                   q.domain, q.source_ip, q.qtype_name
            FROM incidents i
            JOIN alerts a ON i.alert_id = a.id
            JOIN dns_queries q ON a.query_id = q.id
            WHERE {' AND '.join(where)}
            ORDER BY
                CASE UPPER(i.status)
                    WHEN 'OPEN' THEN 0
                    WHEN 'INVESTIGATING' THEN 1
                    WHEN 'CONTAINED' THEN 2
                    ELSE 3
                END,
                i.created_at DESC
            LIMIT %s;
            """,
            tuple(params + [limit]),
        )
        rows = cursor.fetchall()
        return {"status": "success", "count": len(rows), "data": serialize_dates(rows)}


@app.put("/api/incidents/{incident_id}")
def update_incident(incident_id: int, update: IncidentUpdate):
    with db_cursor(dict_rows=False) as (conn, cursor):
        cursor.execute(
            """
            UPDATE incidents
               SET status = COALESCE(%s, status),
                   assigned_to = COALESCE(%s, assigned_to),
                   analyst_notes = COALESCE(%s, analyst_notes),
                   updated_at = CURRENT_TIMESTAMP
             WHERE id = %s
            RETURNING id, alert_id, status;
            """,
            (update.status, update.assigned_to, update.analyst_notes, incident_id),
        )
        row = cursor.fetchone()
        if row is None:
            raise ApiError(404, "Incident not found", f"No incident with id {incident_id}")

        incident_id, alert_id, _incident_status = row

        # Closing a case should close the parent alert too. The alert lifecycle
        # has no CLOSED state, so map CLOSED onto RESOLVED while keeping the
        # incident's more specific state.
        if update.status in ("RESOLVED", "CLOSED", "FALSE POSITIVE"):
            alert_status = "RESOLVED" if update.status == "CLOSED" else update.status
            cursor.execute(
                """
                UPDATE alerts
                   SET status = %s,
                       updated_at = CURRENT_TIMESTAMP
                 WHERE id = %s;
                """,
                (alert_status, alert_id),
            )

        return {"status": "success", "message": "Incident updated"}


# ─── Telemetry & metrics ────────────────────────────────────────────────────
@app.get("/api/queries")
def list_queries(limit: int = Query(60, ge=1, le=500)):
    with db_cursor() as (conn, cursor):
        cursor.execute(
            """
            SELECT q.id, q.timestamp, q.source_ip, q.domain, q.query_type,
                   COALESCE(q.qtype_name, 'A') AS qtype_name, q.ttl,
                   f.entropy, f.entropy_ratio, f.query_length, f.subdomain_length,
                   f.est_payload_bytes, f.encoding, f.is_whitelisted,
                   a.id AS alert_id, a.risk_score, a.severity, a.status
            FROM dns_queries q
            LEFT JOIN dns_features f ON q.id = f.query_id
            LEFT JOIN alerts a ON q.id = a.query_id
            ORDER BY q.timestamp DESC, q.id DESC
            LIMIT %s;
            """,
            (limit,),
        )
        rows = cursor.fetchall()
        return {"status": "success", "count": len(rows), "data": serialize_dates(rows)}


@app.get("/api/metrics")
def get_metrics():
    with db_cursor() as (conn, cursor):
        cursor.execute(
            """
            SELECT
                (SELECT count(*) FROM dns_queries) AS total_queries,
                (SELECT count(*) FROM alerts) AS total_alerts,
                (SELECT count(*) FROM alerts WHERE UPPER(severity) = 'CRITICAL') AS critical_alerts,
                (SELECT count(*) FROM alerts
                  WHERE UPPER(severity) = 'CRITICAL'
                    AND UPPER(status) IN ('OPEN','INVESTIGATING')) AS critical_open_alerts,
                (SELECT count(*) FROM alerts WHERE UPPER(severity) = 'HIGH') AS high_alerts,
                (SELECT count(*) FROM alerts WHERE UPPER(severity) = 'MEDIUM') AS medium_alerts,
                (SELECT count(*) FROM alerts WHERE UPPER(severity) = 'LOW') AS low_alerts,
                (SELECT count(*) FROM alerts WHERE UPPER(status) = 'OPEN') AS open_alerts,
                (SELECT count(*) FROM alerts WHERE UPPER(status) = 'INVESTIGATING') AS investigating_alerts,
                (SELECT count(*) FROM alerts WHERE UPPER(status) IN ('RESOLVED', 'FALSE POSITIVE')) AS resolved_alerts,
                (SELECT count(*) FROM incidents) AS total_incidents,
                (SELECT count(*) FROM incidents WHERE UPPER(COALESCE(status, 'OPEN')) NOT IN ('RESOLVED','CLOSED','FALSE POSITIVE')) AS active_incidents,
                (SELECT COALESCE(ROUND(AVG(risk_score)), 0) FROM alerts) AS avg_risk_score,
                (SELECT COALESCE(count(*), 0) FROM dns_features WHERE is_whitelisted) AS suppressed_queries,
                (SELECT COALESCE(SUM(f.est_payload_bytes), 0)
                   FROM dns_features f
                   JOIN alerts a ON a.query_id = f.query_id) AS total_payload_bytes;
            """
        )
        overview = cursor.fetchone() or {}

        cursor.execute(
            """
            SELECT q.domain, count(*) AS query_count, max(a.risk_score) AS max_risk
            FROM alerts a
            JOIN dns_queries q ON a.query_id = q.id
            GROUP BY q.domain
            ORDER BY query_count DESC, max_risk DESC
            LIMIT 5;
            """
        )
        top_domains = cursor.fetchall()

        cursor.execute(
            """
            SELECT COALESCE(q.source_ip, 'unknown') AS source_ip,
                   count(*) AS alert_count, max(a.risk_score) AS max_risk
            FROM alerts a
            JOIN dns_queries q ON a.query_id = q.id
            GROUP BY q.source_ip
            ORDER BY alert_count DESC, max_risk DESC
            LIMIT 5;
            """
        )
        top_ips = cursor.fetchall()

        # Hourly buckets across the most recent activity, grouped on UTC hour
        # boundaries. Stored timestamps are naive server-local values, so they
        # are first interpreted in the database session timezone and then
        # converted to UTC; the dashboard labels every timestamp as UTC.
        cursor.execute(
            """
            SELECT (
                       date_trunc(
                           'hour',
                           (a.created_at AT TIME ZONE current_setting('TimeZone'))
                               AT TIME ZONE 'UTC'
                       ) AT TIME ZONE 'UTC'
                   ) AS time_bucket,
                   count(*) AS alert_count,
                   round(avg(a.risk_score)) AS avg_risk,
                   max(a.risk_score) AS max_risk
            FROM alerts a
            GROUP BY 1
            ORDER BY 1 DESC
            LIMIT 15;
            """
        )
        timeline = list(reversed(cursor.fetchall()))

        # Severity breakdown for the donut, server-side so it always matches
        # the totals above rather than the current page of alerts.
        severity_breakdown = [
            {"name": "CRITICAL", "value": int(overview.get("critical_alerts") or 0)},
            {"name": "HIGH", "value": int(overview.get("high_alerts") or 0)},
            {"name": "MEDIUM", "value": int(overview.get("medium_alerts") or 0)},
            {"name": "LOW", "value": int(overview.get("low_alerts") or 0)},
        ]

        return {
            "status": "success",
            "data": {
                "overview": serialize_dates(overview),
                "top_domains": serialize_dates(top_domains),
                "top_ips": serialize_dates(top_ips),
                "timeline": serialize_dates(timeline),
                "severity_breakdown": severity_breakdown,
            },
        }


# ─── Simulation & ingestion ─────────────────────────────────────────────────
SCENARIOS = {
    "base32_exfil": [
        ("v1.4g6d8e0f1g2h3j4k5l6m7n8p9q0r1s2t.tunnel-endpoint.biz", 5, "10.0.5.99"),
        ("chunk2.9w8v7u6t5s4r3q2p1o0n9m8l7k6j5h4.tunnel-endpoint.biz", 5, "10.0.5.99"),
        ("chunk3.3k5l7m9n1p2q4r6s8t0v2w4x6y8z0a1.tunnel-endpoint.biz", 5, "10.0.5.99"),
    ],
    "c2_beaconing": [
        ("dnscat.0102030405060708deadbeef.malicious-tunnel.com", 16, "192.168.20.105"),
        ("dnscat.fa73b92c4e1198501234abcd.malicious-tunnel.com", 16, "192.168.20.105"),
        ("dnscat.beeffeed0011223344556677.malicious-tunnel.com", 16, "192.168.20.105"),
    ],
    "iodine_hex": [
        ("7365637265742d646174612d64756d702d3031.c2-command.org", 16, "192.168.10.88"),
        ("7365637265742d646174612d64756d702d3032.c2-command.org", 16, "192.168.10.88"),
        ("61646d696e5f70617373776f72645f68617368.c2-command.org", 10, "192.168.10.88"),
    ],
    "benign": [
        ("api.github.com", 1, "10.0.1.45"),
        ("login.microsoftonline.com", 1, "10.0.1.45"),
        ("www.google.com", 1, "10.0.2.14"),
        ("outlook.office365.com", 1, "10.0.1.45"),
        ("cloudflare.com", 1, "10.0.0.15"),
    ],
}

BENIGN_APEXES = ("github", "google", "microsoft", "cloudflare")


@app.post("/api/simulate")
def simulate_traffic(req: SimulationRequest):
    """
    Inject a synthetic capture into the live pipeline.

    Each injection uses a fresh sub-second timestamp so repeats create new
    rows rather than colliding with the de-duplication index.
    """
    pool = SCENARIOS[req.scenario] if req.scenario != "all" else [q for group in SCENARIOS.values() for q in group]
    chosen = random.sample(pool, min(req.count, len(pool)))

    alerts = incidents = failed = 0
    with db_cursor(dict_rows=False) as (conn, cursor):
        load_whitelist(cursor)
        now = datetime.now()

        for seq, (domain, qtype, src_ip) in enumerate(chosen):
            # Vary the hostname so repeated simulations look like distinct
            # queries from the same tunnel, exactly as a real capture would.
            if "." in domain and not any(apex in domain for apex in BENIGN_APEXES):
                parts = domain.split(".")
                parts[0] = f"{parts[0]}-{random.randint(0x1000, 0xFFFF):x}"
                domain = ".".join(parts)

            # Offset by whole seconds: adding to datetime.microsecond can
            # overflow past 999999 and raise ValueError.
            try:
                result = ingest_record_safe(
                    cursor,
                    domain=domain,
                    query_type=qtype,
                    source_ip=src_ip,
                    timestamp=now + timedelta(seconds=seq),
                    ttl=60,
                )
            except Exception as exc:
                failed += 1
                logger.warning("Simulation record failed (%s): %s", domain, exc)
                continue

            if result["alert_id"]:
                alerts += 1
            if result["incident_id"]:
                incidents += 1

    injected = len(chosen) - failed
    query_word = "query" if injected == 1 else "queries"
    alert_word = "alert" if alerts == 1 else "alerts"
    incident_word = "incident" if incidents == 1 else "incidents"

    return {
        "status": "success",
        "message": (
            f"Injected {injected} {query_word} — {alerts} {alert_word}, "
            f"{incidents} {incident_word} escalated."
        ),
        "attempted_count": len(chosen),
        "injected_count": injected,
        "alerts_generated": alerts,
        "incidents_generated": incidents,
        "failed": failed,
    }


@app.post("/api/ingest/zeek")
def trigger_zeek_ingest():
    result = parse_zeek_dns_log()
    if result.get("status") != "success":
        raise ApiError(404, "Zeek log not found", "Expected zeek/logs/dns.log or ZEEK_LOG_PATH")
    return result


@app.post("/api/ingest/pcap")
def trigger_pcap_ingest():
    try:
        from main import analyze_pcap
    except ImportError as exc:
        raise ApiError(
            503,
            "PCAP support unavailable",
            f"Scapy is not installed: {exc}. Run: pip install scapy",
        ) from exc

    result = analyze_pcap()
    if result.get("status") != "success":
        raise ApiError(404, "PCAP not found", "Expected datasets/suspicious/test_traffic.pcap")
    return result


@app.post("/api/analyze")
def analyze_ad_hoc(domain: str = Query(..., min_length=3, max_length=255),
                   query_type: int = Query(1, ge=1, le=255)):
    """
    Score a single hostname without persisting it.

    Useful for validating a detection, checking whether a whitelist rule would
    suppress something, or reproducing an analyst finding.
    """
    features = extract_dns_features(domain, query_type)
    score, severity, indicators = evaluate_risk(features)
    return {
        "status": "success",
        "data": {
            "domain": features["domain"],
            "risk_score": score,
            "severity": severity,
            "indicators": indicators,
            "features": {k: v for k, v in features.items() if k not in ("domain",)},
        },
    }


# ─── Whitelist ──────────────────────────────────────────────────────────────
@app.get("/api/whitelist")
def list_whitelist():
    with db_cursor() as (conn, cursor):
        cursor.execute("SELECT * FROM whitelist ORDER BY domain_pattern ASC;")
        rows = cursor.fetchall()
        return {"status": "success", "count": len(rows), "data": serialize_dates(rows)}


@app.post("/api/whitelist")
def add_whitelist(entry: WhitelistCreate):
    with db_cursor(dict_rows=False) as (conn, cursor):
        cursor.execute(
            """
            INSERT INTO whitelist (domain_pattern, reason, added_by)
            VALUES (%s, %s, 'analyst')
            ON CONFLICT (domain_pattern) DO UPDATE SET reason = EXCLUDED.reason
            RETURNING id;
            """,
            (entry.domain_pattern, entry.reason),
        )
        cursor.fetchone()
        # Refresh the in-memory rules immediately so the new pattern takes
        # effect for the next ingested query, not the next process restart.
        load_whitelist(cursor)

    return {"status": "success", "message": f"Whitelisted '{entry.domain_pattern}'."}


@app.delete("/api/whitelist/{pattern}")
def delete_whitelist(pattern: str):
    normalized = pattern.strip().strip(".").lower()
    with db_cursor(dict_rows=False) as (conn, cursor):
        cursor.execute(
            "DELETE FROM whitelist WHERE domain_pattern = %s RETURNING id;",
            (normalized,),
        )
        if cursor.fetchone() is None:
            raise ApiError(404, "Whitelist rule not found", normalized)
        load_whitelist(cursor)
    return {"status": "success", "message": f"Removed whitelist rule '{normalized}'."}


# ─── Export ─────────────────────────────────────────────────────────────────
EXPORT_COLUMNS = [
    ("Alert ID", "id"), ("Created", "created_at"), ("Severity", "severity"),
    ("Risk Score", "risk_score"), ("Status", "status"), ("Domain", "domain"),
    ("Source IP", "source_ip"), ("Record Type", "qtype_name"),
    ("Shannon Entropy", "entropy"), ("Entropy Ratio", "entropy_ratio"),
    ("Query Length", "query_length"), ("Subdomain Length", "subdomain_length"),
    ("Est Payload Bytes", "est_payload_bytes"), ("Encoding", "encoding"),
    ("Detection Reason", "detection_reason"), ("Indicators", "indicators"),
    ("Analyst Notes", "analyst_notes"),
]


def _csv_safe(value) -> str:
    """Prevent analyst-controlled text from becoming a spreadsheet formula."""
    text = "" if value is None else str(value)
    if text.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + text
    return text


@app.get("/api/export")
def export_alerts(format: Literal["csv", "json"] = Query("csv")):
    with db_cursor() as (conn, cursor):
        cursor.execute(
            """
            SELECT a.id, a.created_at, a.severity, a.risk_score, a.status,
                   a.detection_reason, a.indicators, a.analyst_notes,
                   q.domain, q.source_ip,
                   COALESCE(q.qtype_name, 'A') AS qtype_name,
                   f.entropy, f.entropy_ratio, f.query_length, f.subdomain_length,
                   f.est_payload_bytes, COALESCE(f.encoding, 'ascii') AS encoding
            FROM alerts a
            JOIN dns_queries q ON a.query_id = q.id
            LEFT JOIN dns_features f ON a.query_id = f.query_id
            ORDER BY a.created_at DESC;
            """
        )
        rows = [dict(r) for r in cursor.fetchall()]

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    if format == "json":
        return JSONResponse(
            status_code=200,
            content=serialize_dates({
                "exported_at": datetime.now(timezone.utc),
                "count": len(rows),
                "alerts": rows,
            }),
            headers={"Content-Disposition": f'attachment; filename="dns-alerts-{stamp}.json"'},
        )

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([label for label, _ in EXPORT_COLUMNS])
    for row in rows:
        writer.writerow([
            _csv_safe(
                serialize_dates(row.get(key)) if isinstance(row.get(key), datetime)
                else row.get(key)
            )
            for _, key in EXPORT_COLUMNS
        ])

    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="dns-alerts-{stamp}.csv"'},
    )


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
