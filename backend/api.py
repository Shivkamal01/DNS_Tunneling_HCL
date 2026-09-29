from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import psycopg2
from psycopg2.extras import RealDictCursor
import uvicorn

app = FastAPI(title="DNS Tunneling Detection API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_CONFIG = {
    "dbname": "dns_tunneling_db",
    "user": "db_user",
    "password": "securepassword123",
    "host": "localhost",
    "port": "5432"
}

def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)

# Data model for the status update
class StatusUpdate(BaseModel):
    status: str

@app.get("/api/alerts")
def get_alerts():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT a.id, a.risk_score, a.severity, a.detection_reason, a.status, a.created_at,
                   q.domain, q.source_ip
            FROM alerts a
            JOIN dns_queries q ON a.query_id = q.id
            ORDER BY a.created_at DESC;
        """)
        alerts = cursor.fetchall()
        return {"status": "success", "data": alerts}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

# NEW ENDPOINT: Update Alert Status
@app.put("/api/alerts/{alert_id}/status")
def update_alert_status(alert_id: int, update: StatusUpdate):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE alerts SET status = %s WHERE id = %s RETURNING id;",
            (update.status, alert_id)
        )
        if cursor.fetchone():
            conn.commit()
            return {"status": "success", "message": "Status updated successfully"}
        else:
            return {"status": "error", "message": "Alert not found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
