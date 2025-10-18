from fastapi import APIRouter, HTTPException, status, Body
from ..schemas import user as user_schema
from ..services import user_service
from ..core.security import get_password_hash

router = APIRouter()

@router.post("/register", response_model=user_schema.UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(user_data: user_schema.UserCreate = Body(...)):
    # 1. Check if the user or email already exists
    existing_user = user_service.get_user_by_email_or_username(email=user_data.email, username=user_data.username)
    if existing_user:
        if existing_user['email'] == user_data.email:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
        if existing_user['username'] == user_data.username:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken")

    # 2. Hash the password SECURELY using passlib/bcrypt
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

@router.get("/users", response_model=list[user_schema.UserResponse])
def get_users():
    """
    Retrieves a list of all users from the database.
    """
    users = user_service.get_users()
    return users