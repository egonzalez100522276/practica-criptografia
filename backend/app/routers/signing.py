from fastapi import APIRouter, Depends, HTTPException, status
from ..core.dependencies import get_current_user
from ..core.security import create_access_token
from ..schemas import user as user_schema
from datetime import timedelta, datetime, timezone

router = APIRouter()

@router.post("/signing-token")
def get_signing_token(
    current_user: user_schema.UserResponse = Depends(get_current_user)
):
    """
    Generates a short-lived signing token for ElGamal signature operations.
    This token is valid for only 30 seconds and can only be used for signing missions.
    
    Security: This prevents sending the user's password repeatedly.
    """
    # Create a very short-lived token (30 seconds)
    signing_token_expires = timedelta(seconds=30)
    expire_time = datetime.now(timezone.utc) + signing_token_expires
    
    signing_token = create_access_token(
        data={
            "sub": current_user['username'],
            "user_id": current_user['id'],
            "role": current_user['role'],
            "purpose": "sign_mission",  # Special purpose flag
            "exp": expire_time
        }
    )
    
    return {
        "signing_token": signing_token,
        "expires_in": 30  # seconds
    }
