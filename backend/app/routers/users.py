from fastapi import APIRouter
from ..schemas import user as user_schema
from ..services import user_service

router = APIRouter()


# NOTE: the UserSchema used here is UNSAFE. 
@router.get("/", response_model=list[user_schema.UserResponseWithPassword])
def get_users():
    """
    Retrieves a list of all users from the database.
    """
    users = user_service.get_users()
    return users

@router.delete("/{user_id}")
def delete_user(user_id: int):
    """
    Deletes a user from the database by their ID.
    """
    user_service.delete_user(user_id)
    return {"message": "User deleted successfully"}