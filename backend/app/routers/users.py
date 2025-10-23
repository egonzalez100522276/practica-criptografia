from fastapi import APIRouter, HTTPException, status, Depends
from ..schemas import user as user_schema
from ..services import user_service
from ..db.database import get_db

router = APIRouter()


# NOTE: the UserSchema used here is UNSAFE. 
@router.get("/", response_model=list[user_schema.UserResponseWithPassword])
def get_users(cursor = Depends(get_db)):
    """
    Retrieves a list of all users from the database.
    """
    users = user_service.get_users(cursor)
    return users

@router.get("/admins", response_model=list[user_schema.UserResponse])
def get_admins(cursor = Depends(get_db)):
    admins = user_service.get_admins(cursor)
    return admins

@router.get("/{user_id}", response_model=user_schema.UserResponseWithPassword)
def get_user_by_id(user_id: int, cursor = Depends(get_db)):
    """
    Retrieves a user from the database by their ID.
    """
    user = user_service.get_user_by_id(cursor, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user

@router.delete("/{user_id}")
def delete_user(user_id: int, cursor = Depends(get_db)):
    """
    Deletes a user from the database by their ID.
    """
    success = user_service.delete_user(cursor, user_id)
    if success:
        return {"message": "User deleted successfully"}
    raise HTTPException(status_code=404, detail="User not found")