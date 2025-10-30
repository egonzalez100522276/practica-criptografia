from fastapi import APIRouter, HTTPException, status, Body, Depends
from fastapi.security import OAuth2PasswordRequestForm
from ..schemas import user as user_schema, token as token_schema
from ..services import user_service, session_service
from ..db.database import get_db
from ..core.security import verify_password, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES
from datetime import timedelta, datetime, timezone

router = APIRouter()
@router.post("/", response_model=token_schema.LoginResponse)
def login_user(form_data: OAuth2PasswordRequestForm = Depends(), cursor = Depends(get_db)):
    """
    Handles user login by verifying credentials from a form.
    - Expects 'username' and 'password' fields.
    - Returns a JWT access token and the user's encrypted private key on success.
    """
    # 1. Find the user in the database by their username.
    user = user_service.get_user_by_username(cursor, form_data.username)

    # 2. Check if the user exists and if the provided password is correct.
    # This uses the SECURE `verify_password` function.
    if not user or not verify_password(form_data.password, user['password_hash']):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
   
    # 3. If credentials are valid, create and return an access token.
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    expire_time = datetime.now(timezone.utc) + access_token_expires
    
    access_token = create_access_token(
        # The 'sub' (subject) is a standard JWT field to identify the user
        data={"sub": user['username'], "user_id": user['id'], "role": user['role'], "exp": expire_time}
    )

    
    # 4. Save the session to the database
    session_service.save_session(cursor, user_id=user['id'], sub=user['username'], role=user['role'], jwt_token=access_token, expires_at=expire_time)

    # 5. Get the user's encrypted private key
    private_key_data = user_service.get_user_private_key(cursor, user['id'])
    if not private_key_data:
        # This should ideally not happen if registration is atomic
        raise HTTPException(status_code=500, detail="Private key not found for user.")

    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "encrypted_private_key": private_key_data['private_key_encrypted']
    }
