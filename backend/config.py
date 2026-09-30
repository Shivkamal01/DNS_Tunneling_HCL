import os
from dotenv import load_dotenv

load_dotenv()

# Database connection credentials — override via .env or environment variables
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME", "dns_tunneling_db"),
    "user": os.getenv("DB_USER", "db_user"),
    "password": os.getenv("DB_PASSWORD", "securepassword123"),
    "host": os.getenv("DB_HOST", "localhost"),
    "port": os.getenv("DB_PORT", "5432"),
}
