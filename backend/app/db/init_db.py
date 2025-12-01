# backend/db/init_db.py
from .database import get_connection, DB_PATH

def create_tables(conn=None) -> None:
    """
    Creates all database tables.
    If no connection is passed, a new one is opened (production mode).
    If a connection is passed, it is reused (ideal for tests with in-memory SQLite).
    """
    close_after = False
    if conn is None:
        conn = get_connection()
        close_after = True

    cursor = conn.cursor()

    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL,
            password_hash TEXT NOT NULL
        );
    """)

    # Table for user public keys
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_keys (
            user_id INTEGER PRIMARY KEY,
            public_key TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );
    """)

    # Table for user Ed25519 public keys
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_ed_keys (
            user_id INTEGER PRIMARY KEY,
            public_key TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );
    """)

    # Table for user private keys
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_private_keys (
            user_id INTEGER PRIMARY KEY,
            private_key_encrypted TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );
    """)

    # Table for user Ed25519 private keys
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_ed_private_keys (
            user_id INTEGER PRIMARY KEY,
            private_key_encrypted TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );
    """)

    # Missions table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS missions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content_encrypted TEXT NOT NULL,
            iv TEXT NOT NULL,
            signature TEXT NOT NULL,
            creator_id INTEGER,
            FOREIGN KEY (creator_id) REFERENCES users (id) ON DELETE CASCADE
        );
    """)

    # Table that maps which user has access to which missions
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mission_access (
            mission_id INTEGER,
            user_id INTEGER,
            encrypted_key BLOB NOT NULL,
            PRIMARY KEY (mission_id, user_id),
            FOREIGN KEY (mission_id) REFERENCES missions (id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );
    """)

    # JWT tokens table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            sub TEXT NOT NULL,
            role TEXT NOT NULL,
            jwt_token TEXT NOT NULL,
            issued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );
    """)

    conn.commit()

    if close_after:
        conn.close()


def seed_demo_user(conn=None) -> None:
    """
    Inserts a demo user into the database.
    It also supports an external connection (for tests or scripts).
    """
    close_after = False
    if conn is None:
        conn = get_connection()
        close_after = True

    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR IGNORE INTO users (username, email, role, password_hash)
        VALUES ('admin', 'admin@example.com', 'admin', 'hashed_password');
    """)
    conn.commit()

    if close_after:
        conn.close()


if __name__ == "__main__":
    conn = get_connection()
    conn.execute("PRAGMA foreign_keys = ON;")
    create_tables(conn)
    # seed_demo_user(conn)
    conn.close()

    print(f"✅ Database initialized with tables: users, user_keys, user_private_keys, user_ed_keys, user_ed_private_keys, missions, mission_access, sessions ({DB_PATH})")
