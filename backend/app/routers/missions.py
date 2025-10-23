from fastapi import APIRouter, HTTPException, status, Depends, Body
from ..schemas import missions as mission_schema
from ..schemas import user as user_schema
from ..services import missions_service
from ..core.dependencies import get_current_user
from ..db.database import get_db

router = APIRouter()

@router.get("/", response_model=list[mission_schema.MissionInDB])
def get_missions(cursor = Depends(get_db)):
    """
    Retrieves a list of all missions from the database.
    """
    return missions_service.get_missions(cursor)

@router.post("/", response_model=mission_schema.MissionResponse, status_code=status.HTTP_201_CREATED)
def create_mission(
    mission_data: mission_schema.MissionCreate,
    current_user: user_schema.UserResponse = Depends(get_current_user),
    cursor = Depends(get_db)
):
    """
    Creates a new mission. Requires authentication.
    The mission content is encrypted and access is granted to the creator and assigned users.
    """
    created_mission = missions_service.create_mission(cursor, content=mission_data.content, creator_id=current_user['id'])
    return created_mission