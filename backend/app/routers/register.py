# Modules
from fastapi import APIRouter, HTTPException, status, Body, Depends
from ..schemas import user as user_schema, token as token_schema
from ..services import user_service, session_service
from ..db.database import get_db
from ..core.security import generate_user_keys, get_password_hash, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES, decrypt_private_key
from ..core.ca import generate_or_load_ca, create_user_certificate

# Other
import os
from base64 import b64encode
from datetime import timedelta, datetime, timezone

# Router
router = APIRouter()

def _register_user_logic(user_data: user_schema.UserCreate, role: str, cursor = Depends(get_db)):
    """
    Internal logic to register a user (agent or admin), generate keys, and create a session.
    """
    # 1. Check if username or email already exist
    if user_service.get_user_by_username(cursor, user_data.username):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken")
    if user_service.get_user_by_email(cursor, user_data.email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    
    # 2. Hash password
    hashed_password = get_password_hash(user_data.password)

    try:
        created_user = user_service.create_user(
            cursor=cursor,
            username=user_data.username,
            email=user_data.email,
            role=role,
            password_hash=hashed_password
        )

        # 4. Generate RSA and Ed25519 key pairs (private keys are encrypted with password)
        public_pem, encrypted_private_pem, ed_public_pem, ed_encrypted_private_pem = generate_user_keys(user_data.password)

        # 5. Generate X.509 certificates
        ca_private_key, ca_certificate = generate_or_load_ca()
        user_cert_pem = create_user_certificate(public_pem, user_data.username, ca_private_key, ca_certificate)
        user_ed_cert_pem = create_user_certificate(ed_public_pem, user_data.username, ca_private_key, ca_certificate)

        # 6. Save public and private keys (with x.509 certificate)

        # RSA
        user_service.save_user_certificate(cursor=cursor, user_id=created_user.id, certificate_pem=user_cert_pem)
        user_service.save_user_private_key(cursor=cursor, user_id=created_user.id, encrypted_private_key=encrypted_private_pem)

        # Ed25519

        user_service.save_user_ed_certificate(cursor=cursor, user_id=created_user.id, certificate_pem=user_ed_cert_pem)
        user_service.save_user_ed_private_key(cursor=cursor, user_id=created_user.id, encrypted_private_key=ed_encrypted_private_pem)

        # 7. Create access token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        expire_time = datetime.now(timezone.utc) + access_token_expires
        access_token = create_access_token(
            data={"sub": created_user.username, "user_id": created_user.id, "role": created_user.role, "exp": expire_time}
        )
        
        #  8. Save the session to the database using the same transaction
        session_service.save_session(cursor, user_id=created_user.id, sub=created_user.username, role=created_user.role, jwt_token=access_token, expires_at=expire_time)

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "encrypted_private_key": keys["rsa_private_encrypted"]
        }
    except Exception as e:
        # The rollback is handled automatically by the `get_db` dependency on exception.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An internal error occurred while creating the user: {e}"
        )

@router.post("/", response_model=token_schema.LoginResponse, status_code=status.HTTP_201_CREATED)
def register_user(user_data: user_schema.UserCreate = Body(...), cursor = Depends(get_db)):
    """
    Register a new user (agent), generate RSA key pair, encrypt private key, and save everything in DB.
    """
    return _register_user_logic(user_data=user_data, role="agent", cursor=cursor)

@router.post("/admin", response_model=token_schema.LoginResponse, status_code=status.HTTP_201_CREATED)
def register_admin(user_data: user_schema.AdminCreate = Body(...), cursor = Depends(get_db)):
    """
    Register a new admin user (leader), generate RSA key pair, encrypt private key, and save everything in DB.
    """
    return _register_user_logic(user_data=user_data, role="leader", cursor=cursor)
