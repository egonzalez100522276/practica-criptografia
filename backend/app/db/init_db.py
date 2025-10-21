# backend/db/init_db.py
from .database import get_connection, DB_PATH

# Create every table in the DB
def create_tables() -> None:
    conn = get_connection()
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
        public_key TEXT NOT NULL,   -- clave pública RSA (en formato PEM)
        FOREIGN KEY (user_id) REFERENCES users (id)
    );
""")
    
    # Table for user private keys
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_private_keys (
        user_id INTEGER PRIMARY KEY,
        private_key_encrypted TEXT NOT NULL,
        salt TEXT NOT NULL,
        nonce TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
);
""")

    # Missions table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS missions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            complete INTEGER NOT NULL DEFAULT 0,
            iv TEXT,
            creator_id INTEGER,
            FOREIGN KEY (creator_id) REFERENCES users (id) 
        );
    """)

    # Table that maps which user has acces to which missions
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mission_access (
        mission_id INTEGER,
        user_id INTEGER,
        encrypted_sym_key TEXT,
        PRIMARY KEY (mission_id, user_id),
        FOREIGN KEY (mission_id) REFERENCES missions (id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                   )
    """)

    # JWT tokens table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            jwt_token TEXT NOT NULL,
            issued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME,
            FOREIGN KEY (user_id) REFERENCES users (id)
            );
    """)

    conn.commit()
    conn.close()

def seed_demo_user() -> None:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR IGNORE INTO users (username, email, role, password_hash)
        VALUES ('admin', 'admin@example.com', 'admin', 'hashed_password');
    """)
    conn.commit()
    conn.close()

# To run, type python -m app.db.init_db
if __name__ == "__main__":
    # Habilitar claves foráneas para la sesión actual
    conn = get_connection()
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.close()

    create_tables()
    seed_demo_user()
    print(f"Database initialized with tables: users, user_keys, user_private_keys, missions, mission_access, sessions ({DB_PATH})")

