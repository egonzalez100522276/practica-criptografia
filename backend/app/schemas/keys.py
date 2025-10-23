from pydantic import BaseModel


class UserPublicKey(BaseModel):
    user_id: int
    public_key: str

class UserPrivateKey(BaseModel):
    user_id: int
    encrypted_private_key: str

class UserKeysResponse(BaseModel):
    user_id: int
    public_key: str
    encrypted_private_key: str
