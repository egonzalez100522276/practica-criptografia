from fastapi import HTTPException, status
from passlib.context import CryptContext
import os
from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import JWTError, jwt # JSON Object Signing and Encryption
from pathlib import Path
from dotenv import load_dotenv

# Cryptography functions
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM 
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Load .env
dotenv_path = Path(__file__).resolve().parent.parent.parent / '.env'
load_dotenv(dotenv_path)

# Constants
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is not set in environment variables.")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# --- JWT ---
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Creates a JWT access token."""
    to_encode = data.copy()
    if expires_delta and "exp" not in to_encode:
        expire = datetime.now(timezone.utc) + expires_delta
        to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> dict:
    """
    Decodes and validates a JWT access token.
    Raises HTTP 401 if invalid or expired.
    Returns the decoded payload if valid.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        # Captura errores como firma inválida, expiración, etc.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )
   

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
    """DEPRECATED: Use generate_user_keys instead for password-based encryption."""

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")
    return private_pem, public_pem


def generate_user_keys(password: str) -> tuple[str, str]:
    """
    Generate an RSA key pair. The private key is encrypted in PEM format using the user's password.
    Returns (public_pem, encrypted_private_pem)
    """
    # 1. Generate RSA key pair
    private_key, public_key = generate_rsa_key_pair()

    # 2. Serialize public key to PEM (no encryption)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    # 3. Serialize private key to PEM, encrypting it with the user's password
    encrypted_private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8'))
    ).decode("utf-8")

    return public_pem, encrypted_private_pem


def decrypt_private_key(encrypted_private_key, password):
    """
    Decrypts a user's private key using the password they used to log in.
    Returns the private key object.
    """
    try:
        # Load the PEM data into a private key object, providing the password for decryption.
        private_key = serialization.load_pem_private_key(
            encrypted_private_key.encode('utf-8'),
            password=password.encode('utf-8')
        )
        return private_key
    except Exception:
        # This could fail if the password is wrong, or data is corrupt
        return None


# --- AES ---
def encrypt_with_aes(content: str) -> tuple[str, str, bytes]: # Changed return type hint
    # Generate AES key
    aes_key = os.urandom(32)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    
    # Encrypt content
    encrypted_content = aesgcm.encrypt(nonce, content.encode("utf-8"), None) # content is str, encode to bytes

    return encrypted_content.hex(), nonce.hex(), aes_key # Return aes_key as bytes, others as hex strings