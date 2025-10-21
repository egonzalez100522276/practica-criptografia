from passlib.context import CryptContext
import os
from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import JWTError, jwt # JSON Object Signing and Encryption
# Cryptography functions
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM 

# --- JWT ---

# Constants
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is not set in environment variables.")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Creates a JWT access token."""
    to_encode = data.copy()
    if expires_delta and "exp" not in to_encode:
        expire = datetime.now(timezone.utc) + expires_delta
        to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> Optional[dict]:
    """Decodes the access token. Returns payload if valid, else None."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None
   

# --- Password Hashing ---

# Configure the context for password hashing.
# Argon2 is the new default, but we keep bcrypt for legacy hashes.
pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against a hashed password."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Hashes a password using the default scheme (argon2)."""
    return pwd_context.hash(password)


# --- RSA ---

# Functions
def generate_rsa_key_pair():
    """Generate an RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()   

    return private_key, public_key

def serialize_keys_in_pem(private_key, public_key):
    """Serialize a pair of keys in PEM format."""

    # Public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    # Private key (no encryption here, caller must encrypt manually)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    return private_pem, public_pem


def generate_user_keys(password: str):
    """
    Generate RSA key pair and encrypt the private key with a key derived from the user's password.
    Returns (public_pem, encrypted_private_key, salt, nonce)
    """

    # 1. Generate RSA key pair
    private_key, public_key = generate_rsa_key_pair()

    # 2. Serialize keys in PEM format
    private_pem, public_pem = serialize_keys_in_pem(private_key, public_key)

    # 4. Derive AES key from password using scrypt
    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    aes_key = kdf.derive(password.encode())


    # 5. Encrypt private key with AES-GCM
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    encrypted_private_key = aesgcm.encrypt(nonce, private_pem, None)

    # 6. Return all
    return public_pem, encrypted_private_key, salt, nonce


