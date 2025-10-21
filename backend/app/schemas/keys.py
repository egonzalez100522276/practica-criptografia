from pydantic import BaseModel


class UserPublicKey(BaseModel):
    user_id: int
    public_key: str

class UserPrivateKey(BaseModel):
    user_id: int
    encrypted_private_key: str  # Base64 para poder enviarlo como JSON
    salt: str  # Base64
    nonce: str  # Base64

class UserKeysResponse(BaseModel):
    user_id: int
    public_key: str
    encrypted_private_key: str
    salt: str
    nonce: str
