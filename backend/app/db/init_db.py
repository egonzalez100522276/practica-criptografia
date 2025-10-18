# backend/db/init_db.py
from .database import get_connection, DB_PATH

def create_tables():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
    """)

    conn.commit()
    conn.close()


# To run, type python -m app.db.init_db
if __name__ == "__main__":
    create_tables()
    print(f"'users' table created or already exists in {DB_PATH}")
