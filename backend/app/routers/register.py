# Modules
from fastapi import APIRouter, HTTPException, status, Body
from ..schemas import user as user_schema
from ..services import user_service, session_service
from ..core.security import generate_user_keys, get_password_hash, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES

# Other
import os
from base64 import b64encode
from datetime import timedelta, datetime, timezone

# Router
router = APIRouter()

def _register_user_logic(user_data: user_schema.UserCreate, role: str):
    """
    Internal logic to register a user (agent or admin), generate keys, and create a session.
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
            role=role,
            password_hash=hashed_password
        )

        # 4. Generate RSA key pair (private key is encrypted with password)
        public_pem, encrypted_private_pem = generate_user_keys(user_data.password)

        # 5. Save public key
        user_service.save_user_public_key(user_id=created_user.id, public_key=public_pem)

        # 6. Save encrypted private key directly
        user_service.save_user_private_key(user_id=created_user.id, encrypted_private_key=encrypted_private_pem)

        # 7. Create and return an access token for the newly registered user
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        expire_time = datetime.now(timezone.utc) + access_token_expires
        access_token = create_access_token(
            data={"sub": created_user.username, "user_id": created_user.id, "role": created_user.role, "exp": expire_time}
        )
        
        # 8. Save the session to the database
        session_service.save_session(user_id=created_user.id, sub=created_user.username, role=created_user.role, jwt_token=access_token, expires_at=expire_time)

        return {"access_token": access_token, "token_type": "bearer"}
    except Exception as e:
        # Basic error handling. In a real app, you might want to delete the created user if key generation fails.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An internal error occurred while creating the user: {e}"
        )

@router.post("/", response_model=user_schema.Token, status_code=status.HTTP_201_CREATED)
def register_user(user_data: user_schema.UserCreate = Body(...)):
    """
    Register a new user (agent), generate RSA key pair, encrypt private key, and save everything in DB.
    """
    return _register_user_logic(user_data, role="agent")

@router.post("/admin", response_model=user_schema.Token, status_code=status.HTTP_201_CREATED)
def register_admin(user_data: user_schema.UserCreate = Body(...)):
    """
    Register a new admin user (leader), generate RSA key pair, encrypt private key, and save everything in DB.
    """
    return _register_user_logic(user_data, role="leader")
