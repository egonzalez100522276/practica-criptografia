import json
from ..core.security import encrypt_with_aes, decrypt_private_key
from ..services import user_service
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ..schemas.missions import MissionContent # Import MissionContent

def get_missions(cursor) -> list:
    """
    Retrieves all missions from the database.
    """
    cursor.execute("SELECT * FROM missions")
    rows = cursor.fetchall()
    missions = [dict(row) for row in rows]
    return missions

def get_missions_by_creator(cursor, creator_id: int) -> list:
    """
    Retrieves all missions created by a specific user.
    """
    cursor.execute("SELECT * FROM missions WHERE creator_id = ?", (creator_id,))
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


def decrypt_mission(cursor, mission_id: int, user_id: int, password: str) -> dict | None:
    """
    Decrypts the content of a mission for a specific user.
    Returns the decrypted mission content or None if access is denied or an error occurs.
    """
    # 1. Retrieve the encrypted mission from the DB
    cursor.execute("SELECT * FROM missions WHERE id = ?", (mission_id,))
    mission = cursor.fetchone()
    if not mission:
        return None
    
    # 2. Retrieve the user's encrypted private key and decrypt it with their password
    private_key_data = user_service.get_user_private_key(cursor, user_id)
    if not private_key_data:
        return None
    user_private_key = decrypt_private_key(private_key_data['private_key_encrypted'], password)
    if not user_private_key:
        # This likely means a wrong password was provided
        return None
    
    # 3. Retrieve the encrypted AES key for this specific mission and user
    cursor.execute("SELECT encrypted_key FROM mission_access WHERE mission_id = ? AND user_id = ?", (mission_id, user_id))
    access_data = cursor.fetchone()
    if not access_data:
        # The user does not have access to this mission
        return None
    
    # 4. Decrypt the AES key using the user's private RSA key
    encrypted_aes_key = bytes.fromhex(access_data['encrypted_key'])
    aes_key = user_private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=padding.hashes.SHA256()), algorithm=padding.hashes.SHA256(), label=None)
    )

    # 5. Decrypt the mission content using the now-decrypted AES key
    encrypted_content = bytes.fromhex(mission['content_encrypted'])
    iv = bytes.fromhex(mission['iv'])
    aesgcm = AESGCM(aes_key)
    decrypted_content_bytes = aesgcm.decrypt(iv, encrypted_content, None)
    decrypted_content_json = decrypted_content_bytes.decode('utf-8')
    
    # 6. Return the full mission object with the decrypted content
    return {"id": mission['id'], "creator_id": mission['creator_id'], "content": json.loads(decrypted_content_json)}

def decrypt_missions(cursor, missions: list, user_id: int, password: str) -> list:
    """
    Iterates over a list of missions and decrypts each one for the given user.
    Skips missions that cannot be decrypted (e.g., wrong password, no access).
    """
    decrypted_list = []
    for mission in missions:
        decrypted_mission = decrypt_mission(cursor, mission['id'], user_id, password)
        if decrypted_mission:
            decrypted_list.append(decrypted_mission)
    
    return decrypted_list
    
    