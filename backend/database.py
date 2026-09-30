import psycopg2
from config import DB_CONFIG

def init_db():
    """Connects to PostgreSQL and creates the necessary project tables."""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()

        # 1. Table for raw DNS Queries
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS dns_queries (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source_ip VARCHAR(50),
                domain VARCHAR(255),
                query_type INT,
                ttl INT
            );
        """)

        # 2. Table for Extracted Features
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS dns_features (
                id SERIAL PRIMARY KEY,
                query_id INT REFERENCES dns_queries(id) ON DELETE CASCADE,
                query_length INT,
                entropy FLOAT
            );
        """)

        # 3. Table for Security Alerts
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id SERIAL PRIMARY KEY,
                query_id INT REFERENCES dns_queries(id) ON DELETE CASCADE,
                risk_score INT,
                severity VARCHAR(20),
                detection_reason TEXT,
                status VARCHAR(20) DEFAULT 'OPEN',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # 4. Table for Incident Management
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id SERIAL PRIMARY KEY,
                alert_id INT REFERENCES alerts(id) ON DELETE CASCADE,
                source_ip VARCHAR(50),
                domain VARCHAR(255),
                severity VARCHAR(20),
                status VARCHAR(20) DEFAULT 'INVESTIGATING',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        conn.commit()
        cursor.close()
        conn.close()
        print("Database tables created successfully!")

    except Exception as e:
        print(f"Error connecting to database: {e}")

if __name__ == "__main__":
    init_db()
