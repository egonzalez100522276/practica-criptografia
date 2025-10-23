from app.db.database import get_connection

class UserObj:
    def __init__(self, id, username, email, role):
        self.id = id
        self.username = username
        self.email = email
        self.role = role
    
    # Used by endpoints when they need to return a UserObj
    def to_dict(self):
        return vars(self)


def create_user(cursor, username: str, email: str, role: str, password_hash: str) -> dict:
    """
    Creates a new user in the database using the provided cursor.
    Does NOT commit the transaction.
    """
    cursor.execute("""
        INSERT INTO users (username, email, role, password_hash)
        VALUES (?, ?, ?, ?); 
    """, (username, email, role, password_hash))
    user_id = cursor.lastrowid
    # Return the user data inside an object
    return UserObj(user_id, username, email, role)


def save_user_public_key(cursor, user_id: int, public_key: str):
    """ Insert public key into DB using the provided cursor. Does NOT commit. """
    cursor.execute("""
        INSERT INTO user_keys (user_id, public_key)
        VALUES (?, ?) 
    """, (user_id, public_key))

def save_user_private_key(cursor, user_id: int, encrypted_private_key: str):
    """ Insert private key into DB using the provided cursor. Does NOT commit. """
    cursor.execute("""
        INSERT INTO user_private_keys (user_id, private_key_encrypted)
        VALUES (?, ?)
    """, (user_id, encrypted_private_key))

def get_user_public_key(cursor, user_id: int):
    """
    Finds a user's public key by user_id.
    """
    cursor.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))
    cursor.execute("SELECT public_key FROM user_keys WHERE user_id = ?", (user_id,))
    key = cursor.fetchone()
    return key

def get_user_private_key(cursor, user_id: int):
    """
    Finds a user's private key data by user_id.
    """
    cursor.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))
    cursor.execute("SELECT * FROM user_private_keys WHERE user_id = ?", (user_id,))
    key = cursor.fetchone()
    return key

def get_user_by_id(cursor, user_id: int):
    """
    Finds a user by ID.
    """
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    return dict(user) if user else None


def get_user_by_username(cursor, username: str):
    """
    Finds a user by username.
    """
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    return dict(user) if user else None

def get_user_by_email(cursor, email: str):
    """
    Finds a user by email.
    """
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    return dict(user) if user else None

def get_users(cursor) -> list:
    """
    Retrieves all users from the database.
    """
    cursor.execute("SELECT * FROM users")
    rows = cursor.fetchall()
    users = [dict(row) for row in rows]
    return users

def get_admins(cursor) -> list:
    """
    Retrieves all admins from the database.
    """
    cursor.execute("SELECT * FROM users WHERE role = 'leader'")
    rows = cursor.fetchall()
    admins = [dict(row) for row in rows]
    return admins


def delete_user(cursor, user_id: int) -> bool:
    """
    Deletes a user from the database by their ID. Returns True if successful.
    """
    user_exists = cursor.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user_exists:
        return False
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return True
