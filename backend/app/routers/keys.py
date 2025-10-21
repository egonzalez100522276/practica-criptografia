from fastapi import APIRouter, HTTPException, status
from ..schemas import keys as key_schema
from ..services import user_service

router = APIRouter()

@router.get("/{user_id}", response_model=key_schema.UserKeysResponse, status_code=status.HTTP_200_OK)
def get_user_keys(user_id: int):
    """
    Retrieves the public and encrypted private keys for a specific user.
    """
    public_key_data = user_service.get_user_public_key(user_id)
    private_key_data = user_service.get_user_private_key(user_id)

    if not public_key_data or not private_key_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Keys for user with id {user_id} not found"
        )

    # Combine the data from both tables into the response model
    return key_schema.UserKeysResponse(
        user_id=user_id,
        public_key=public_key_data['public_key'],
        encrypted_private_key=private_key_data['private_key_encrypted'],
        salt=private_key_data['salt'],
        nonce=private_key_data['nonce']
    )