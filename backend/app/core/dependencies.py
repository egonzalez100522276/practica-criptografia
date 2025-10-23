from fastapi import Depends, HTTPException, status, Header
from ..db.database import get_db
from ..services import session_service, user_service
from ..schemas.user import UserResponse


def get_current_user(
    authorization: str = Header(None), 
    cursor = Depends(get_db)
) -> UserResponse:
    """
    FastAPI dependency to get the current authenticated user.

    It validates the JWT from the 'Authorization: Bearer <token>' header,
    checks if the session is active in the database, and returns the
    full user object.

    Raises HTTPException with status 401 if authentication fails.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header is missing or invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = authorization.split(" ")[1]

    user_from_token = session_service.get_user_from_token(cursor, token)
    if not user_from_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired session")

    full_user = user_service.get_user_by_id(cursor, user_from_token.id)
    if not full_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User associated with token not found")
    
    return full_user