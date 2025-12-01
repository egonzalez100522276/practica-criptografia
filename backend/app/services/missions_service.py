import json
from ..core.security import encrypt_with_aes, decrypt_private_key, decrypt_ed_private_key, sign
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

def get_shared_missions_for_user(cursor, user_id: int) -> list:
    """
    Retrieves all missions shared with a specific user, excluding those they created themselves.
    """
    cursor.execute("""
        SELECT m.*
        FROM missions m
        JOIN mission_access ma ON m.id = ma.mission_id
        WHERE ma.user_id = ? AND m.creator_id != ?
    """, (user_id, user_id))
    rows = cursor.fetchall()
    missions = [dict(row) for row in rows]
    return missions


def create_mission(cursor, content: MissionContent, creator_id: int, password: str) -> dict: 
    """
    Creates a new mission, encrypts its content, signs it with the creator's Ed25519 key,
    and grants access to specified users.
    This is an atomic transaction managed by the `get_db` dependency.
    """

    # Convert the Pydantic model to a JSON string before encrypting
    content_json_str = content.model_dump_json() # Use model_dump_json() for Pydantic v2

    # --- 0. Retrieve and decrypt the creator's Ed25519 private key ---
    ed_private_key_pem = user_service.get_user_ed_private_key(cursor, creator_id)
    if not ed_private_key_pem:
        raise Exception(f"No Ed25519 key found for user {creator_id}")

    ed_private_key_obj = decrypt_ed_private_key(ed_private_key_pem, password)
    if not ed_private_key_obj:
        raise Exception("Wrong password or corrupted key. Cannot decrypt Ed25519 private key.")

    # --- 1. Sign the mission content ---
    signature_b64 = sign(content_json_str, ed_private_key_obj)

    # --- 2. Encrypt the mission content with a new, single-use AES key ---
    encrypted_content_hex, nonce_hex, aes_key_bytes = encrypt_with_aes(content_json_str) 

    # --- 3. Insert the encrypted mission into the database with the signature ---
    cursor.execute(
        "INSERT INTO missions (content_encrypted, iv, creator_id, signature) VALUES (?, ?, ?, ?)",
        (encrypted_content_hex, nonce_hex, creator_id, signature_b64)
    )
    mission_id = cursor.lastrowid

    # --- 4. Get all users who need access: the creator and all admins ---
    admins = user_service.get_admins(cursor)
    user_ids_with_access = {creator_id} | {admin['id'] for admin in admins}

    # --- 5. For each user, encrypt the AES key with their public key and save it ---
    for user_id in user_ids_with_access:
        public_key_data = user_service.get_user_public_key(cursor, user_id)
        if not public_key_data or not public_key_data.get('public_key'):
            raise Exception(f"Could not find public key for user ID: {user_id}. Mission creation aborted.")

        public_key_pem = public_key_data['public_key']
        user_public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))

        encrypted_aes_key_for_user = user_public_key.encrypt(
            aes_key_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=padding.hashes.SHA256()), 
                algorithm=padding.hashes.SHA256(), 
                label=None
            )
        )

        cursor.execute(
            "INSERT INTO mission_access (mission_id, user_id, encrypted_key) VALUES (?, ?, ?)",
            (mission_id, user_id, encrypted_aes_key_for_user)
        )

    # --- 6. Return the original content and signature for the response ---
    return {
        "id": mission_id,
        "content": content.model_dump(),
        "creator_id": creator_id,
        "signature": signature_b64
    }


from fastapi import HTTPException, status
from ..core.security import verify
from cryptography.hazmat.primitives import serialization

def decrypt_mission(cursor, mission_id: int, user_id: int, user_private_key) -> dict:
    """
    Decrypts the content of a mission for a specific user and verifies the signature.
    Raises HTTPException if signature is invalid or access is denied.
    """
    # 1. Retrieve the encrypted mission from the DB
    cursor.execute("SELECT * FROM missions WHERE id = ?", (mission_id,))
    mission = cursor.fetchone()
    if not mission or not user_private_key:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied or invalid key.")
    
    # 2. Retrieve the encrypted AES key for this user
    cursor.execute(
        "SELECT encrypted_key FROM mission_access WHERE mission_id = ? AND user_id = ?", 
        (mission_id, user_id)
    )
    access_data = cursor.fetchone()
    if not access_data:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User does not have access to this mission.")
    
    # 3. Decrypt the AES key
    encrypted_aes_key = access_data['encrypted_key']
    aes_key = user_private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=padding.hashes.SHA256()),
            algorithm=padding.hashes.SHA256(),
            label=None
        )
    )

    # 4. Decrypt the mission content
    encrypted_content = bytes.fromhex(mission['content_encrypted'])
    iv = bytes.fromhex(mission['iv'])
    aesgcm = AESGCM(aes_key)
    decrypted_content_bytes = aesgcm.decrypt(iv, encrypted_content, None)
    decrypted_content_json = decrypted_content_bytes.decode('utf-8')
    content_dict = json.loads(decrypted_content_json)

    # 5. Get creator info and their Ed25519 public key
    creator = user_service.get_user_by_id(cursor, mission['creator_id'])
    creator_username = creator['username'] if creator else 'Unknown Agent'
    ed_public_key_data = user_service.get_user_ed_public_key(cursor, mission['creator_id'])
    if not ed_public_key_data:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"No Ed25519 public key found for user {mission['creator_id']}")
    
    ed_public_key_pem = ed_public_key_data['public_key']
    ed_public_key_obj = serialization.load_pem_public_key(ed_public_key_pem.encode('utf-8'))

    # 6. Verify signature
    content_json_str_for_verify = decrypted_content_bytes.decode("utf-8")  # exactamente lo mismo bytes que se descifró
    if not verify(content_json_str_for_verify, mission['signature'], ed_public_key_obj):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid signature for mission ID {mission['id']}.")

    return {
        "id": mission['id'],
        "creator_id": mission['creator_id'],
        "creator_username": creator_username,
        "content": content_dict,
        "signature": mission['signature']
    }


def decrypt_missions(cursor, missions: list, user_id: int, user_private_key) -> list:
    """
    Iterates over a list of missions and decrypts each one for the given user.
    Skips missions that cannot be decrypted (e.g., wrong password, no access).
    """
    decrypted_list = []
    for mission in missions:
        decrypted_mission = decrypt_mission(cursor, mission['id'], user_id, user_private_key)
        if decrypted_mission:
            decrypted_list.append(decrypted_mission)
    
    return decrypted_list

def share_mission(cursor, mission_id: int, sharer_id: int, sharer_private_key, target_user_ids: list[int]):
    """
    Shares a mission with a list of target users.
    1. Decrypts the mission's AES key using the sharer's private key.
    2. Re-encrypts the AES key for each target user using their public key.
    3. Inserts the new access records into the database.
    """
    
    # 1. Get the encrypted AES key for the user who is sharing the mission
    cursor.execute("SELECT encrypted_key FROM mission_access WHERE mission_id = ? AND user_id = ?", (mission_id, sharer_id))
    access_data = cursor.fetchone()
    if not access_data:
        raise Exception("Sharer does not have access to this mission.")

    # 2. Decrypt the AES key using the sharer's private key
    encrypted_aes_key_for_sharer = access_data['encrypted_key']
    aes_key = sharer_private_key.decrypt(
        encrypted_aes_key_for_sharer,
        padding.OAEP(mgf=padding.MGF1(algorithm=padding.hashes.SHA256()), algorithm=padding.hashes.SHA256(), label=None)
    )

    # 3. For each target user, get their public key and re-encrypt the AES key
    for user_id in target_user_ids:
        public_key_data = user_service.get_user_public_key(cursor, user_id)
        if not public_key_data or not public_key_data.get('public_key'):
            raise Exception(f"Could not find public key for user ID: {user_id}")

        target_public_key = serialization.load_pem_public_key(public_key_data['public_key'].encode('utf-8'))

        encrypted_aes_key_for_target = target_public_key.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=padding.hashes.SHA256()), algorithm=padding.hashes.SHA256(), label=None)
        )

        # 4. Insert (or replace) the access record for the target user
        cursor.execute(
            "INSERT OR REPLACE INTO mission_access (mission_id, user_id, encrypted_key) VALUES (?, ?, ?)",
            (mission_id, user_id, encrypted_aes_key_for_target)
        )