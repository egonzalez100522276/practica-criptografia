from ..db.database import get_db
from ..core.security import encrypt_with_aes
from ..services import user_service
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

def get_missions(cursor) -> list:
    """
    Retrieves all missions from the database.
    """
    cursor.execute("SELECT * FROM missions")
    rows = cursor.fetchall()
    missions = [dict(row) for row in rows]
    return missions

def create_mission(cursor, content: str, creator_id: int, assigned_user_ids: list[int]) -> dict:
    """
    Creates a new mission, encrypts its content, and grants access to specified users.
    This is an atomic transaction managed by the `get_db` dependency.
    """
    # 1. Encrypt the mission content with a new, single-use AES key
    encrypted_content_hex, nonce_hex, aes_key_hex = encrypt_with_aes(content)
    aes_key = bytes.fromhex(aes_key_hex)

    # 2. Insert the encrypted mission into the database
    cursor.execute(
        "INSERT INTO missions (content_encrypted, iv, creator_id) VALUES (?, ?, ?)",
        (encrypted_content_hex, nonce_hex, creator_id)
    )
    mission_id = cursor.lastrowid

    # 3. For each assigned user, encrypt the AES key with their public RSA key
    all_assigned_ids = set(assigned_user_ids + [creator_id]) # Creator always has access
    for user_id in all_assigned_ids:
        user_key_data = user_service.get_user_public_key(cursor, user_id)
        if not user_key_data:
            raise Exception(f"Public key for user {user_id} not found.")
        
        public_key = serialization.load_pem_public_key(user_key_data['public_key'].encode('utf-8'))
        
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=padding.hashes.SHA256()), algorithm=padding.hashes.SHA256(), label=None)
        )
        
        cursor.execute("INSERT INTO mission_access (mission_id, user_id, encrypted_sym_key) VALUES (?, ?, ?)", (mission_id, user_id, encrypted_aes_key.hex()))

    return {"id": mission_id, "content": content, "creator_id": creator_id}
