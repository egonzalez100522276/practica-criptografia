import os
import sys
import pytest
from app.core import pki, elgamal, security
from app.db import init_db, database
from app.services import user_service, missions_service
from app.schemas.missions import MissionContent
import json
import base64

# Add backend to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

DB_PATH = "test_spy_agency_flow.db"
database.DB_PATH = DB_PATH

def setup_module():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = database.get_connection()
    init_db.create_tables(conn)
    conn.close()

def teardown_module():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

def test_full_flow():
    print("\n--- Testing Full Flow (Register -> Create Mission -> Share) ---")
    
    conn = database.get_connection()
    cursor = conn.cursor()
    
    try:
        # 1. Register User 1 (Agent 007)
        password_1 = "bond"
        keys_1 = security.generate_user_keys(password_1)
        user_1 = user_service.create_user(cursor, "agent007", "007@mi6.com", "agent", "hashed_pw")
        user_service.save_user_public_key(
            cursor, user_1.id, keys_1["rsa_public"], keys_1["rsa_public_signature"], 
            keys_1["elgamal_public"], keys_1["elgamal_public_signature"]
        )
        user_service.save_user_private_key(
            cursor, user_1.id, keys_1["rsa_private_encrypted"], keys_1["elgamal_private_encrypted"]
        )
        conn.commit()
        print("User 1 registered with signed keys.")
        
        # 2. Register User 2 (Q)
        password_2 = "gadgets"
        keys_2 = security.generate_user_keys(password_2)
        user_2 = user_service.create_user(cursor, "q", "q@mi6.com", "admin", "hashed_pw")
        user_service.save_user_public_key(
            cursor, user_2.id, keys_2["rsa_public"], keys_2["rsa_public_signature"], 
            keys_2["elgamal_public"], keys_2["elgamal_public_signature"]
        )
        user_service.save_user_private_key(
            cursor, user_2.id, keys_2["rsa_private_encrypted"], keys_2["elgamal_private_encrypted"]
        )
        conn.commit()
        print("User 2 registered with signed keys.")
        
        # 3. Create Mission (User 1 creates)
        mission_content = MissionContent(title="Operation Skyfall", description="Defeat Silva")
        result = missions_service.create_mission(cursor, mission_content, user_1.id, password_1)
        conn.commit()
        
        assert result["id"] is not None
        assert result["signature"] is not None
        print("Mission created successfully (Signatures verified during creation).")
        
        # 4. Verify Mission Signature
        cursor.execute("SELECT * FROM missions WHERE id = ?", (result["id"],))
        mission_db = cursor.fetchone()
        signature_str = mission_db["signature"]
        r, s = map(int, signature_str.split(","))
        
        elgamal_pub_json = keys_1["elgamal_public"]
        elgamal_pub = json.loads(elgamal_pub_json) # [P, G, y]
        y = elgamal_pub[2]
        
        content_json_str = mission_content.model_dump_json()
        
        is_valid = elgamal.verify(content_json_str, (r, s), y)
        assert is_valid == True
        print("Mission ElGamal signature verified.")

        # 5. Share Mission
        password_3 = "moneypenny"
        keys_3 = security.generate_user_keys(password_3)
        user_3 = user_service.create_user(cursor, "moneypenny", "m@mi6.com", "agent", "hashed_pw")
        user_service.save_user_public_key(
            cursor, user_3.id, keys_3["rsa_public"], keys_3["rsa_public_signature"], 
            keys_3["elgamal_public"], keys_3["elgamal_public_signature"]
        )
        conn.commit()
        
        user_1_priv_pem = security.decrypt_private_key(keys_1["rsa_private_encrypted"], password_1)
        
        missions_service.share_mission(cursor, result["id"], user_1.id, user_1_priv_pem, [user_3.id])
        conn.commit()
        print("Mission shared successfully (Recipient signature verified).")
        
        # 6. Tamper Test
        cursor.execute("UPDATE user_keys SET public_key_signature = ? WHERE user_id = ?", 
                    (base64.b64encode(b"fakesig").decode(), user_3.id))
        conn.commit()
        
        try:
            missions_service.share_mission(cursor, result["id"], user_1.id, user_1_priv_pem, [user_3.id])
            assert False, "Should have failed due to bad signature"
        except Exception as e:
            assert "Signature verification failed" in str(e) or "Security check failed" in str(e)
            print("Tamper check passed: " + str(e))

    finally:
        conn.close()

if __name__ == "__main__":
    setup_module()
    try:
        test_full_flow()
        print("\nALL TESTS PASSED!")
    finally:
        teardown_module()
