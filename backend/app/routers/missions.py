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

@router.post("/{mission_id}/decrypt", response_model=mission_schema.MissionResponse)
def decrypt_mission_endpoint(
    mission_id: int,
    body: mission_schema.MissionDecryptRequest,
    current_user: user_schema.UserResponse = Depends(get_current_user),
    cursor = Depends(get_db)
):
    """
    Provisional endpoint to test mission decryption.
    Requires the user's password in the request body to decrypt their private key.
    """
    decrypted_mission = missions_service.decrypt_mission(
        cursor, mission_id=mission_id, user_id=current_user['id'], password=body.password
    )

    if not decrypted_mission:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Could not decrypt mission. Check if you have access or if the password is correct.")

    return decrypted_mission

@router.get("/mine", response_model=list[mission_schema.MissionResponse])
def get_and_decrypt_my_missions(
    body: mission_schema.MissionDecryptRequest,
    current_user: user_schema.UserResponse = Depends(get_current_user),
    cursor = Depends(get_db)
):
    """
    Retrieves all missions created by the currently authenticated user and decrypts them.
    Requires the user's password in the request body.
    """
    missions = missions_service.get_missions_by_creator(cursor, creator_id=current_user['id'])
    return missions_service.decrypt_missions(cursor, missions, current_user['id'], body.password)
    