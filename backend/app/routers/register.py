# backend/routers/user.py
from base64 import b64encode
from fastapi import APIRouter, HTTPException, status, Body
from ..schemas import user as user_schema
from ..schemas import keys as key_schema
from ..services import user_service
from ..core.security import get_password_hash
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

router = APIRouter()

def generate_user_keys(password: str):
    """
    Generate RSA key pair and encrypt the private key with a key derived from the user's password.
    Returns (public_pem, encrypted_private_key, salt, nonce)
    """
    # 1. Generate RSA key pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public_key = private_key.public_key()

    # 2. Serialize public key in PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    # 3. Serialize private key in PEM format (no encryption here, we encrypt manually)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # 4. Derive AES key from password using scrypt
    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    aes_key = kdf.derive(password.encode())

    # 5. Encrypt private key with AES-GCM
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    encrypted_private_key = aesgcm.encrypt(nonce, private_pem, None)

    return public_pem, encrypted_private_key, salt, nonce



@router.post("/", response_model=user_schema.UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(user_data: user_schema.UserCreate = Body(...)):
    """
    Register a new user, generate RSA key pair, encrypt private key, and save everything in DB.
    """

    # 1. Check if username or email already exist
    if user_service.get_user_by_username(user_data.username):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken")
    if user_service.get_user_by_email(user_data.email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    # 2. Hash password
    hashed_password = get_password_hash(user_data.password)

    try:
        # 3. Save user in DB
        created_user = user_service.create_user(
            username=user_data.username,
            email=user_data.email,
            role='agent',
            password_hash=hashed_password
        )

        # 4. Generate RSA key pair
        public_pem, encrypted_private_key, salt, nonce = generate_user_keys(user_data.password)

        # 5. Save public key using schema
        public_key_obj = key_schema.UserPublicKey(
            user_id=created_user.id,
            public_key=public_pem
        )
        user_service.save_user_public_key(**public_key_obj.dict())

        # 6. Save encrypted private key using schema
        private_key_obj = key_schema.UserPrivateKey(
            user_id=created_user.id,
            encrypted_private_key=b64encode(encrypted_private_key).decode(),
            salt=b64encode(salt).decode(),
            nonce=b64encode(nonce).decode()
        )
        user_service.save_user_private_key(**private_key_obj.dict())

        # 7. Return created user
        return created_user

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An internal error occurred while creating the user: {e}"
        )