from app.db.database import get_connection
from datetime import datetime
from typing import Optional
from ..core.security import decode_access_token
from .user_service import UserObj
from datetime import datetime

def get_sessions(cursor) -> list:
    """
    Retrieves all sessions from the database.
    """
    cursor.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))
    cursor.execute("SELECT * FROM sessions;")
    rows = cursor.fetchall()
    return rows

def save_session(cursor, user_id: int, sub: str, role: str, jwt_token: str, expires_at:datetime):
    """Saves a new session token to the database."""
    
    cursor.execute(
        "INSERT INTO sessions (user_id, sub, role,  jwt_token, expires_at) VALUES (?, ?, ?, ?, ?)",
        (user_id, sub, role, jwt_token, expires_at)
    )

def get_sessions_by_user_id(cursor, user_id: int) -> list:
    """Retrieves all active sessions for a given user."""
    cursor.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))
    cursor.execute(
        "SELECT * FROM sessions WHERE user_id = ? AND expires_at > CURRENT_TIMESTAMP",
        (user_id)
    )
    rows = cursor.fetchall()
    return rows

def get_user_from_token(cursor, token: str) -> Optional[UserObj]:
    """
    Decodes a JWT, validates its payload, and checks if the session exists in the database.
    Returns the user object if valid, otherwise None.
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
    cursor.execute(
        "SELECT 1 FROM sessions WHERE jwt_token = ? AND expires_at > CURRENT_TIMESTAMP",
        (token,)
    )
    session_exists = cursor.fetchone()

    if not session_exists:
        return None

    return UserObj(user_id, username, None, user_role)
