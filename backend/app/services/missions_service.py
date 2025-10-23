import json
from ..core.security import encrypt_with_aes # No need for encrypt_with_rsa directly here, use crypto lib
from ..services import user_service
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from ..schemas.missions import MissionContent # Import MissionContent

def get_missions(cursor) -> list:
    """
    Retrieves all missions from the database.
    """
    cursor.execute("SELECT * FROM missions")
    rows = cursor.fetchall()
    missions = [dict(row) for row in rows]
    return missions

def create_mission(cursor, content: MissionContent, creator_id: int) -> dict: # Changed content type
    """
    Creates a new mission, encrypts its content, and grants access to specified users.
    This is an atomic transaction managed by the `get_db` dependency.
    """
    # Convert the Pydantic model to a JSON string before encrypting
    content_json_str = content.model_dump_json() # Use model_dump_json() for Pydantic v2

    # 1. Encrypt the mission content with a new, single-use AES key
    encrypted_content_hex, nonce_hex, aes_key_bytes = encrypt_with_aes(content_json_str) # Get aes_key_bytes
    
    # 2. Insert the encrypted mission into the database
    cursor.execute(
        "INSERT INTO missions (content_encrypted, iv, creator_id) VALUES (?, ?, ?)",
        (encrypted_content_hex, nonce_hex, creator_id)
    )
    mission_id = cursor.lastrowid

    # 3. Encrypt the AES key with the creator's public RSA key
    public_key_data = user_service.get_user_public_key(cursor, creator_id)
    if not public_key_data or not public_key_data.get('public_key'):
        raise Exception(f"Public key for creator {creator_id} not found.")
    
    public_key_pem = public_key_data['public_key']
    
    creator_public_key = serialization.load_pem_public_key(
        public_key_pem.encode('utf-8')
    )
    
    encrypted_aes_key_for_creator = creator_public_key.encrypt(
        aes_key_bytes, # Encrypt the actual bytes of the AES key
        padding.OAEP(mgf=padding.MGF1(algorithm=padding.hashes.SHA256()), algorithm=padding.hashes.SHA256(), label=None)
    )
    
    # 4. Save the encrypted AES key in the mission_access table for the creator
    cursor.execute(
        "INSERT INTO mission_access (mission_id, user_id, encrypted_key) VALUES (?, ?, ?)",
        (mission_id, creator_id, encrypted_aes_key_for_creator.hex())
    )

    # The content returned should be the original content, not the encrypted one.
    return {"id": mission_id, "content": content.model_dump(), "creator_id": creator_id} # Return original content for response
