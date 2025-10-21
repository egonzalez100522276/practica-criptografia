from app.db.database import get_connection

def create_user(username: str, email: str, role: str, password_hash: str) -> dict:
    """
    Creates a new user in the database.
    """
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO users (username, email, role, password_hash)
            VALUES (?, ?, ?, ?); 
        """, (username, email, role, password_hash))
        user_id = cursor.lastrowid
        conn.commit()
        return {"id": user_id, "username": username, "email": email, "role": role}
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def save_user_public_key(user_id: int, public_key: str):
    """ Insert public key into DB """
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO user_keys (user_id, public_key)
            VALUES (?, ?)
        """, (user_id, public_key))
        conn.commit()
    finally:
        conn.close()


def save_user_private_key(user_id: int, encrypted_private_key: bytes, salt: bytes, nonce: bytes):
    """ 
    Insert private key into DB
    """
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO user_private_keys (user_id, private_key_encrypted, salt, nonce)
            VALUES (?, ?, ?, ?)
        """, (user_id, encrypted_private_key, salt, nonce))
        conn.commit()
    finally:
        conn.close()



def get_user_by_username(username: str):
    """
    Finds a user by username.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None

def get_user_by_email(email: str):
    """
    Finds a user by email.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None

def get_users() -> list:
    """
    Retrieves all users from the database.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    rows = cursor.fetchall()
    conn.close()
    
    users = [dict(row) for row in rows]
    return users