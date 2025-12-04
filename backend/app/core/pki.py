import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

CA_KEY_PATH = "ca_private_key.pem"

def get_ca_private_key():
    """
    Loads the CA private key from disk or generates it if it doesn't exist.
    """
    if os.path.exists(CA_KEY_PATH):
        with open(CA_KEY_PATH, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
    else:
        # Generate a new CA key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        # Save it to disk
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(CA_KEY_PATH, "wb") as f:
            f.write(pem)
            
    return private_key

def get_ca_public_key_pem():
    private_key = get_ca_private_key()
    public_key = private_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

def sign_data(data: bytes) -> bytes:
    """
    Signs data using the CA private key.
    Returns the signature in bytes.
    """
    private_key = get_ca_private_key()
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(data: bytes, signature: bytes) -> bool:
    """
    Verifies a signature against the CA public key.
    """
    private_key = get_ca_private_key()
    public_key = private_key.public_key()
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
