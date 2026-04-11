import psycopg2

# BAD: credentials hardcoded directly in source
DB_HOST = "db.internal.example.com"
DB_PORT = 5432
DB_NAME = "production_db"
DB_USER = "admin"
DB_PASSWORD = "Sup3rS3cr3t!Pass#2024"

def get_connection():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )