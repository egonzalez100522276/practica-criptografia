from app.db.database import get_connection
from datetime import datetime
from typing import Optional
from ..core.security import decode_access_token

class UserObj:
    def __init__(self, id, username, email, role):
        self.id = id
        self.username = username
        self.email = email
        self.role = role


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

        # Return the user data inside an object
        return UserObj(user_id, username, email, role)
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

def get_user_public_key(user_id: int):
    """
    Finds a user's public key by user_id.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))
    cursor.execute("SELECT * FROM user_keys WHERE user_id = ?", (user_id,))
    key = cursor.fetchone()
    conn.close()
    return key

def get_user_private_key(user_id: int):
    """
    Finds a user's private key data by user_id.
    """
    conn = get_connection()
    # Using dictionary=True to get column names
    cursor = conn.cursor()
    cursor.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))
    cursor.execute("SELECT * FROM user_private_keys WHERE user_id = ?", (user_id,))
    key = cursor.fetchone()
    conn.close()
    return key



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


def delete_user(user_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

def save_session(user_id: int, jwt_token: str, expires_at: datetime):
    """Saves a new session token to the database."""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO sessions (user_id, jwt_token, expires_at) VALUES (?, ?, ?)",
            (user_id, jwt_token, expires_at)
        )
        conn.commit()
    finally:
        conn.close()

def get_sessions_by_user_id(user_id: int) -> list:
    """Retrieves all active sessions for a given user."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, user_id, jwt_token, issued_at, expires_at FROM sessions WHERE user_id = ? AND expires_at > CURRENT_TIMESTAMP",
        (user_id,)
    )
    rows = cursor.fetchall()
    conn.close()
    
    sessions = [dict(row) for row in rows]
    return sessions

def get_user_from_token(token: str) -> Optional[dict]:
    """
    Decodes a JWT, validates its payload, and checks if the session exists in the database.
    Returns the user payload dictionary if valid, otherwise None.
    """
    payload = decode_access_token(token)
    if not payload:
        return None

    user_id: int = payload.get("user_id")
    username: str = payload.get("sub")
    user_role: str = payload.get("role")

    if user_id is None or username is None or user_role is None:
        return None

    # Security enhancement: Check if the token exists in our sessions table
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT 1 FROM sessions WHERE jwt_token = ? AND expires_at > CURRENT_TIMESTAMP",
        (token,)
    )
    session_exists = cursor.fetchone()
    conn.close()

    if not session_exists:
        return None

    return UserObj(user_id, username, None, user_role)