import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "spy-agency.db"

def get_connection():
    """
    Returns a connection to the SQLite database.
    Uses sqlite3.Row to access columns by name.
    """
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    # Habilitar el soporte para claves foráneas (necesario para ON DELETE CASCADE)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    return conn
