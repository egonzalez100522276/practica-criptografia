from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from .services import user_service

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")
# NOT IN USE RIGHT NOW
async def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    Dependency to get the current authenticated user from the JWT token.
    Raises HTTPException 401 if credentials are invalid or token is missing/expired.
    Returns a dictionary with user_id, username, and role.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    user = user_service.get_user_from_token(token)

    if user is None:
        raise credentials_exception
    
    return user
