from pydantic import BaseModel

class UserKeysResponse(BaseModel):
    user_id: int
    certificate: str
    public_key: str
    encrypted_private_key: str
    ed_public_key: str
    ed_encrypted_private_key: str

class DecryptRequest(BaseModel):
    username: str
    password: str

class DecryptedPrivateKeyResponse(BaseModel):
    private_key_pem: str