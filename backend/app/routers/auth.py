from fastapi import APIRouter, HTTPException, status, Body, Depends
from fastapi.security import OAuth2PasswordRequestForm
from ..schemas import user as user_schema
from ..services import user_service
from ..core.security import get_password_hash, verify_password

router = APIRouter()

@router.post("/register", response_model=user_schema.UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(user_data: user_schema.UserCreate = Body(...)):
    # 1. Check if username or email already exist. This gives us full control over the validation order.
    if user_service.get_user_by_username(user_data.username):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken")
    
    if user_service.get_user_by_email(user_data.email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    # 2. Hash the password SECURELY using the configured scheme (argon2)
    hashed_password = get_password_hash(user_data.password)

    try:
        # 3. Save to the DB and get the created user
        created_user = user_service.create_user(
            username=user_data.username,
            email=user_data.email,
            password_hash=hashed_password
        )
        # 4. Return the created user (FastAPI handles serialization)
        return created_user
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An internal error occurred while creating the user: {e}"
        )

@router.post("/login", response_model=user_schema.UserResponse)
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
