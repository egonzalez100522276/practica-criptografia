import json
from ..core.security import encrypt_with_aes, decrypt_private_key, decrypt_data_with_password
from ..core import elgamal, pki
from ..services import user_service
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ..schemas.missions import MissionContent # Import MissionContent
import base64

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


def create_mission(cursor, content: MissionContent, creator_id: int, creator_password: str) -> dict: # Changed content type
    """
    Creates a new mission, encrypts its content, signs it, and grants access to specified users.
    This is an atomic transaction managed by the `get_db` dependency.
    """

    # Convert the Pydantic model to a JSON string before encrypting
    content_json_str = content.model_dump_json() # Use model_dump_json() for Pydantic v2
    
    # --- ElGamal Signing ---
    # 1. Get creator's encrypted ElGamal private key
    creator_keys = user_service.get_user_private_key(cursor, creator_id)
    if not creator_keys or not creator_keys.get('elgamal_private_key_encrypted'):
        raise Exception("ElGamal private key not found for user.")
        
    elgamal_private_encrypted = creator_keys['elgamal_private_key_encrypted']
    
    # 2. Decrypt ElGamal private key
    elgamal_private_key_str = decrypt_data_with_password(elgamal_private_encrypted, creator_password)
    if not elgamal_private_key_str:
        raise Exception("Failed to decrypt ElGamal private key (wrong password?).")
    elgamal_private_key = int(elgamal_private_key_str)
    
    # 3. Sign the content (hash of title + description)
    # We sign the raw content string to ensure integrity of what the user sees
    signature_tuple = elgamal.sign(content_json_str, elgamal_private_key)
    # Store signature as "r,s" string
    signature_str = f"{signature_tuple[0]},{signature_tuple[1]}"


    # --- AES Encryption ---
    # 1. Encrypt the mission content with a new, single-use AES key
    encrypted_content_hex, nonce_hex, aes_key_bytes = encrypt_with_aes(content_json_str) # Get aes_key_bytes
    
    # 2. Insert the encrypted mission into the database
    cursor.execute(
        "INSERT INTO missions (content_encrypted, iv, signature, creator_id) VALUES (?, ?, ?, ?)",
        (encrypted_content_hex, nonce_hex, signature_str, creator_id)
    )
    mission_id = cursor.lastrowid

    # 3. Get all users who need access: the creator and all admins.
    admins = user_service.get_admins(cursor)
    # Use a set to automatically handle duplicates (e.g., if the creator is an admin)
    user_ids_with_access = {creator_id} | {admin['id'] for admin in admins}

    # 4. For each user, encrypt the AES key with their public key and save it.
    for user_id in user_ids_with_access:
        public_key_data = user_service.get_user_public_key(cursor, user_id)
        if not public_key_data or not public_key_data.get('public_key'):
            # In a real-world scenario, you might want to decide how to handle this.
            # For now, we'll raise an exception to ensure data integrity.
            raise Exception(f"Could not find public key for user ID: {user_id}. Mission creation aborted.")

        public_key_pem = public_key_data['public_key']
        
        # VERIFY CA SIGNATURE
        public_key_sig_b64 = public_key_data.get('public_key_signature')
        if not public_key_sig_b64:
             raise Exception(f"Public key for user {user_id} is not signed by CA. Security check failed.")
        
        if not pki.verify_signature(public_key_pem.encode(), base64.b64decode(public_key_sig_b64)):
             raise Exception(f"CA Signature verification failed for user {user_id}. Public key may be tampered.")

        user_public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))

        encrypted_aes_key_for_user = user_public_key.encrypt(
            aes_key_bytes,
            padding.OAEP(mgf=padding.MGF1(algorithm=padding.hashes.SHA256()), algorithm=padding.hashes.SHA256(), label=None)
        )

        cursor.execute(
            "INSERT INTO mission_access (mission_id, user_id, encrypted_key) VALUES (?, ?, ?)",
            (mission_id, user_id, encrypted_aes_key_for_user)
        )

    # The content returned should be the original content, not the encrypted one.
    return {
        "id": mission_id, 
        "content": content.model_dump(), 
        "creator_id": creator_id,
        "signature": signature_str,
        "signature_valid": True
    } 


def decrypt_mission(cursor, mission_id: int, user_id: int, user_private_key) -> dict | None:
    """
    Decrypts the content of a mission for a specific user.
    Returns the decrypted mission content or None if access is denied or an error occurs.
    """
    # 1. Retrieve the encrypted mission from the DB
    cursor.execute("SELECT * FROM missions WHERE id = ?", (mission_id,))
    mission = cursor.fetchone()
    if not mission:
        return None
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
    encrypted_aes_key = access_data['encrypted_key']
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
    
    # NEW: Get creator's username to include in the response
    creator = user_service.get_user_by_id(cursor, mission['creator_id'])
    creator_username = creator['username'] if creator else 'Unknown Agent'

    # --- Verify ElGamal signature for integrity/authenticity ---
    signature_valid = None
    try:
        if mission['signature']:
            sig_parts = mission['signature'].split(",")
            if len(sig_parts) == 2:
                signature_tuple = (int(sig_parts[0]), int(sig_parts[1]))
                creator_keys = user_service.get_user_public_key(cursor, mission['creator_id'])
                if creator_keys and creator_keys.get('elgamal_public_key'):
                    elgamal_public = json.loads(creator_keys['elgamal_public_key'])
                    # elgamal_public = (P, G, y)
                    public_key_y = elgamal_public[2]
                    signature_valid = elgamal.verify(decrypted_content_json, signature_tuple, public_key_y)
                else:
                    signature_valid = False
            else:
                signature_valid = False
        else:
            signature_valid = False
    except Exception:
        signature_valid = False

    # 6. Return the full mission object with the decrypted content
    return {
        "id": mission['id'], 
        "creator_id": mission['creator_id'], 
        "creator_username": creator_username, 
        "content": json.loads(decrypted_content_json),
        "signature": mission['signature'],
        "signature_valid": signature_valid
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

        public_key_pem = public_key_data['public_key']

        # VERIFY CA SIGNATURE
        public_key_sig_b64 = public_key_data.get('public_key_signature')
        if not public_key_sig_b64:
             raise Exception(f"Public key for user {user_id} is not signed by CA. Security check failed.")
        
        if not pki.verify_signature(public_key_pem.encode(), base64.b64decode(public_key_sig_b64)):
             raise Exception(f"CA Signature verification failed for user {user_id}. Public key may be tampered.")

        target_public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))

        encrypted_aes_key_for_target = target_public_key.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=padding.hashes.SHA256()), algorithm=padding.hashes.SHA256(), label=None)
        )

        # 4. Insert (or replace) the access record for the target user
        cursor.execute(
            "INSERT OR REPLACE INTO mission_access (mission_id, user_id, encrypted_key) VALUES (?, ?, ?)",
            (mission_id, user_id, encrypted_aes_key_for_target)
        )
