from fastapi import APIRouter, HTTPException, Header, status, Depends
from typing import List
from ..schemas import user as user_schema
from ..services import session_service
from ..services import user_service
from ..db.database import get_db
from jose import JWTError

router = APIRouter()

@router.get("/", response_model=List[user_schema.SessionResponse])
def get_sessions(cursor = Depends(get_db)):
    """
    Retrieves all active sessions for the currently authenticated user.
    """
    return session_service.get_sessions(cursor)



@router.get("/validate", response_model=user_schema.UserResponse)
def validate_token_endpoint(authorization: str = Header(None), cursor = Depends(get_db)):
    """
    Validates the JWT from the Authorization header. It checks the signature,
    expiration, and if the session is still active in the database.
    Returns the full user object on success.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header is missing or invalid",
        )
    
    token = authorization.split(" ")[1]
    
    try:
        # 1. Validate token and session existence
        user_from_token = session_service.get_user_from_token(cursor, token)
        if not user_from_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired session")

        # 2. Fetch the full user details from the database to get the email
        full_user = user_service.get_user_by_id(cursor, user_from_token.id)
        if not full_user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User associated with token not found")
        
        return full_user
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token (e.g., expired or bad signature)")