from fastapi import APIRouter
from typing import List
from ..schemas import user as user_schema
from ..services import session_service

router = APIRouter()

@router.get("/", response_model=List[user_schema.SessionResponse])
def get_sessions():
    """
    Retrieves all active sessions for the currently authenticated user.
    """
    return session_service.get_sessions()
