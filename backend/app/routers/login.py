from fastapi import APIRouter, HTTPException, status, Body, Depends
from fastapi.security import OAuth2PasswordRequestForm
from ..schemas import user as user_schema
from ..services import user_service
from ..core.security import get_password_hash, verify_password

router = APIRouter()

@router.post("/", response_model=user_schema.UserResponse)
def login_user(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Handles user login by verifying credentials from a form.
    - It expects 'username' and 'password' fields.
    - It returns user data on success.
    """
    # 1. Find the user in the database by their username.
    user = user_service.get_user_by_username(form_data.username)

    # 2. Check if the user exists and if the provided password is correct.
    # This uses the SECURE `verify_password` function.
    if not user or not verify_password(form_data.password, user['password_hash']):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    # 3. If credentials are valid, return the user's data.
    return user
