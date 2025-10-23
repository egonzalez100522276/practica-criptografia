from fastapi import APIRouter, HTTPException, status, Depends
from ..schemas import keys as key_schema
from ..services import user_service
from ..db.database import get_db
from cryptography.hazmat.primitives import serialization
from ..core.security import decrypt_private_key

router = APIRouter()

@router.get("/{user_id}", response_model=key_schema.UserKeysResponse, status_code=status.HTTP_200_OK)
def get_user_keys(user_id: int, cursor = Depends(get_db)):
    """
    Retrieves the public and encrypted private keys for a specific user.
    """
    public_key_data = user_service.get_user_public_key(cursor, user_id)
    private_key_data = user_service.get_user_private_key(cursor, user_id)

    if not public_key_data or not private_key_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Keys for user with id {user_id} not found"
        )

    # Combine the data from both tables into the response model
    return key_schema.UserKeysResponse(
        user_id=user_id,
        public_key=public_key_data['public_key'],
        encrypted_private_key=private_key_data['private_key_encrypted']
    )

@router.post("/decrypt", response_model=key_schema.DecryptedPrivateKeyResponse)
def decrypt_user_private_key(
    body: key_schema.DecryptRequest,
    cursor = Depends(get_db)
):
    """
    Finds a user by username, retrieves their encrypted private key,
    and decrypts it using the provided password.
    """
    user = user_service.get_user_by_username(cursor, body.username)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    private_key_data = user_service.get_user_private_key(cursor, user['id'])
    if not private_key_data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Private key not found for user")

    decrypted_key_obj = decrypt_private_key(private_key_data['private_key_encrypted'], body.password)
    if not decrypted_key_obj:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect password")

    private_pem = decrypted_key_obj.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode('utf-8')
    return {"private_key_pem": private_pem}