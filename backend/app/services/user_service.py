from app.db.database import get_connection

def create_user(username: str, email: str, password_hash: str) -> dict:
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO users (username, email, password_hash)
            VALUES (?, ?, ?);
        """, (username, email, password_hash))
        user_id = cursor.lastrowid
        conn.commit()
        # Return a dictionary that matches the UserResponse schema
        return {"id": user_id, "username": username, "email": email}
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()


def get_user_by_email_or_username(email: str, username: str):
    """Finds a user by email or username to check for existence."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ? OR username = ?", (email, username))
    user = cursor.fetchone()
    conn.close()
    return user

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