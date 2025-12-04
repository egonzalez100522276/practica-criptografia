from app.db.database import get_connection
from app.core.ca import generate_or_load_ca, validate_user_certificate
from cryptography import x509
from cryptography.hazmat.primitives import serialization

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


# --- RSA keys ---
def save_user_certificate(cursor, user_id: int, certificate_pem: str):
    """ Insert User X.509 certificate into DB using the provided cursor. Does NOT commit. """
    cursor.execute("""
        INSERT INTO user_keys (user_id, x509_certificate)
        VALUES (?, ?) 
    """, (user_id, certificate_pem))

def save_user_private_key(cursor, user_id: int, encrypted_private_key: str):
    """ Insert RSA private key into DB using the provided cursor. Does NOT commit. """
    cursor.execute("""
        INSERT INTO user_private_keys (user_id, private_key_encrypted, elgamal_private_key_encrypted)
        VALUES (?, ?, ?)
    """, (user_id, encrypted_private_key, elgamal_private_key_encrypted))

def get_user_certificate(cursor, user_id: int):
    """
    Finds a user's X.509 certificate by user_id.
    """
    cursor.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))
    cursor.execute("SELECT x509_certificate FROM user_keys WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    return row['x509_certificate'] if row else None

def get_user_public_key(cursor, user_id: int):
    """
    Finds a user's RSA public key by user_id.
    It retrieves the X.509 certificate, validates it, and extracts the public key.
    """
    cursor.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))
    cursor.execute("SELECT x509_certificate FROM user_keys WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    
    if not row:
        return None

    cert_pem = row['x509_certificate']
    
    # Validate certificate
    _, ca_cert = generate_or_load_ca()
    if not validate_user_certificate(cert_pem, ca_cert):
        raise ValueError(f"Invalid or expired certificate for user {user_id}")

    # Extract public key from certificate
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    public_key = cert.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return {'public_key': public_pem}

def get_user_private_key(cursor, user_id: int):
    """
    Finds a user's RSA private key data by user_id.
    """
    cursor.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))
    cursor.execute("SELECT * FROM user_private_keys WHERE user_id = ?", (user_id,))
    key = cursor.fetchone()
    return key


# --- Ed25519 keys ---
def save_user_ed_certificate(cursor, user_id: int, certificate_pem: str):
    """ Insert Ed25519 public key certificate into DB using the provided cursor. Does NOT commit. """
    cursor.execute("""
        INSERT INTO user_ed_keys (user_id, x509_certificate)
        VALUES (?, ?) 
    """, (user_id, certificate_pem))

def save_user_ed_private_key(cursor, user_id: int, encrypted_private_key: str):
    """ Insert Ed25519 private key into DB using the provided cursor. Does NOT commit. """
    cursor.execute("""
        INSERT INTO user_ed_private_keys (user_id, private_key_encrypted)
        VALUES (?, ?)
    """, (user_id, encrypted_private_key))

def get_user_ed_public_key(cursor, user_id: int):
    """
    Finds a user's Ed25519 public key by user_id.
    """
    cursor.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))
    cursor.execute("SELECT x509_certificate FROM user_ed_keys WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    
    if not row:
        return None

    cert_pem = row['x509_certificate']
    
    # Validate certificate
    _, ca_cert = generate_or_load_ca()
    if not validate_user_certificate(cert_pem, ca_cert):
        raise ValueError(f"Invalid or expired Ed25519 certificate for user {user_id}")

    # Extract public key from certificate
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    public_key = cert.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return {'public_key': public_pem}

def get_user_ed_private_key(cursor, user_id: int):
    """
    Finds a user's Ed25519 private key data by user_id.
    """
    cursor.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))
    cursor.execute("SELECT private_key_encrypted FROM user_ed_private_keys WHERE user_id = ?", (user_id,))
    key = cursor.fetchone()
    return key


# --- User queries ---
def get_user_by_id(cursor, user_id: int):
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    return dict(user) if user else None

def get_user_by_username(cursor, username: str):
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    return dict(user) if user else None

def get_user_by_email(cursor, email: str):
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    return dict(user) if user else None

def get_users(cursor) -> list:
    cursor.execute("SELECT * FROM users")
    rows = cursor.fetchall()
    return [dict(row) for row in rows]

def get_admins(cursor) -> list:
    cursor.execute("SELECT * FROM users WHERE role = 'leader'")
    rows = cursor.fetchall()
    return [dict(row) for row in rows]

def delete_user(cursor, user_id: int) -> bool:
    user_exists = cursor.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user_exists:
        return False
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return True
