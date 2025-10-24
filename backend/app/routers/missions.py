from fastapi import APIRouter, HTTPException, status, Depends, Body
from ..schemas import missions as mission_schema
from ..schemas import user as user_schema
from ..services import user_service, missions_service
from ..core.dependencies import get_current_user
from ..db.database import get_db
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

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
    The mission content is encrypted and access is granted to the creator and the admins.
    """
    created_mission = missions_service.create_mission(cursor, content=mission_data.content, creator_id=current_user['id'])
    return created_mission

@router.post("/mine/decrypt", response_model=list[mission_schema.MissionResponse])
def get_and_decrypt_my_created_missions(
    body: mission_schema.MissionDecryptWithKeyRequest,
    current_user: user_schema.UserResponse = Depends(get_current_user),
    cursor = Depends(get_db)
):
    """
    Retrieves and decrypts all missions created by the currently authenticated user.
    Requires the user's private key in PEM format in the request body.
    """
    # Decrypt the user's private key from the request body
    try:
        user_private_key = serialization.load_pem_private_key(body.private_key_pem.encode(), password=None)
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid private key format.")

    # Get missions created by the user
    missions = missions_service.get_missions_by_creator(cursor, creator_id=current_user['id'])
    return missions_service.decrypt_missions(cursor, missions, current_user['id'], user_private_key)


@router.post("/{mission_id}/share", status_code=status.HTTP_200_OK)
def share_mission_endpoint(
    mission_id: int,
    body: mission_schema.MissionShareRequest,
    current_user: user_schema.UserResponse = Depends(get_current_user),
    cursor = Depends(get_db)
):
    """
    Shares a mission with a list of users.
    Requires the sharer's private key to decrypt and re-encrypt the mission key.
    """
    if not body.user_ids:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No users selected to share with.")

    try:
        sharer_private_key = serialization.load_pem_private_key(body.private_key_pem.encode(), password=None)
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid private key format.")

    try:
        missions_service.share_mission(cursor, mission_id, current_user['id'], sharer_private_key, body.user_ids)
        return {"message": f"Mission shared successfully with {len(body.user_ids)} user(s)."}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.get("/shared/", response_model=list[mission_schema.MissionInDB])
def get_shared_with_me(
    current_user: user_schema.UserResponse = Depends(get_current_user),
    cursor = Depends(get_db)
):
    """
    Retrieves all missions that have been shared with the currently authenticated user.
    """
    return missions_service.get_shared_missions_for_user(cursor, user_id=current_user['id'])

@router.post("/shared/decrypt", response_model=list[mission_schema.MissionResponse])
def get_and_decrypt_shared_missions(
    body: mission_schema.MissionDecryptWithKeyRequest,
    current_user: user_schema.UserResponse = Depends(get_current_user),
    cursor = Depends(get_db)
):
    """
    Retrieves and decrypts all missions shared with the currently authenticated user.
    Requires the user's private key in PEM format in the request body.
    """
    try:
        user_private_key = serialization.load_pem_private_key(body.private_key_pem.encode(), password=None)
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid private key format.")

    missions = missions_service.get_shared_missions_for_user(cursor, user_id=current_user['id'])
    return missions_service.decrypt_missions(cursor, missions, current_user['id'], user_private_key)
    