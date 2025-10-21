from ..db.database import get_connection


def get_sessions() -> list:
    """
    Retrieves all users from the database.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sessions;")
    rows = cursor.fetchall()
    conn.close()
    
    users = [dict(row) for row in rows]
    return users
