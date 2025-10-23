from app.db.database import get_connection

def get_missions() -> list:
    """
    Retrieves all missions from the database.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM missions")
    rows = cursor.fetchall()
    conn.close()
    
    missions = [dict(row) for row in rows]
    return missions

def create_mission(title:str, description: str, creator: str) -> None:
    """
    Creates a new mission in the database.
    """
    # Initialize cursor
    conn = get_connection()
    cursor = conn.cursor()

    # Get user_id from the creator
    cursor.execute("SELECT id FROM users WHERE username = ?", (creator))
    creator_id = cursor.fetchone()[0]


    # Add mission to the DB
    cursor.execute("INSERT INTO missions (content_encrypted, iv, creator_id) VALUES (?, ?)", (title, description, creator_id))
    conn.commit()
    conn.close()
