import os
import sys
import pytest
from app.core import pki, elgamal, security
from app.db import init_db, database
import json

# Add backend to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

DB_PATH = "test_spy_agency.db"
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
    if os.path.exists("ca_private_key.pem"):
        # Keep CA key for inspection if needed, or remove
        pass

def test_pki_ca_generation():
    print("\n--- Testing CA Key Generation ---")
    private_key = pki.get_ca_private_key()
    assert private_key is not None
    public_key_pem = pki.get_ca_public_key_pem()
    assert "BEGIN PUBLIC KEY" in public_key_pem
    print("CA Key Pair generated successfully.")

def test_ca_signing_verification():
    print("\n--- Testing CA Signing & Verification ---")
    data = b"Hello World"
    signature = pki.sign_data(data)
    assert len(signature) > 0
    
    is_valid = pki.verify_signature(data, signature)
    assert is_valid == True
    
    is_invalid = pki.verify_signature(b"Hello World Modified", signature)
    assert is_invalid == False
    print("CA Signing and Verification works.")

def test_elgamal_math():
    print("\n--- Testing ElGamal Math ---")
    pub, priv = elgamal.generate_keys()
    P, G, y = pub
    x = priv
    
    message = "Secret Mission"
    r, s = elgamal.sign(message, x)
    
    is_valid = elgamal.verify(message, (r, s), y)
    assert is_valid == True
    
    is_invalid = elgamal.verify("Fake Mission", (r, s), y)
    assert is_invalid == False
    print("ElGamal Math works.")

def test_user_key_generation_and_signing():
    print("\n--- Testing User Key Generation & CA Signing ---")
    password = "strongpassword"
    keys = security.generate_user_keys(password)
    
    assert "rsa_public" in keys
    assert "rsa_public_signature" in keys
    assert "elgamal_public" in keys
    assert "elgamal_public_signature" in keys
    
    # Verify RSA Public Key Signature
    rsa_pub_pem = keys["rsa_public"]
    rsa_sig_b64 = keys["rsa_public_signature"]
    import base64
    rsa_sig = base64.b64decode(rsa_sig_b64)
    
    assert pki.verify_signature(rsa_pub_pem.encode(), rsa_sig) == True
    print("User RSA Public Key correctly signed by CA.")
    
    # Verify ElGamal Public Key Signature
    elgamal_pub_str = keys["elgamal_public"]
    elgamal_sig_b64 = keys["elgamal_public_signature"]
    elgamal_sig = base64.b64decode(elgamal_sig_b64)
    
    assert pki.verify_signature(elgamal_pub_str.encode(), elgamal_sig) == True
    print("User ElGamal Public Key correctly signed by CA.")

if __name__ == "__main__":
    setup_module()
    try:
        test_pki_ca_generation()
        test_ca_signing_verification()
        test_elgamal_math()
        test_user_key_generation_and_signing()
        print("\nALL TESTS PASSED!")
    finally:
        teardown_module()
