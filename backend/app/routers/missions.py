from fastapi import APIRouter, HTTPException, status
from ..schemas import user as user_schema
from ..services import missions_service

router = APIRouter()

@router.get("/", response_model=list[user_schema.UserResponse])
def get_missions():
    """
    Retrieves a list of all missions from the database.
    """
    return missions_service.get_missions()