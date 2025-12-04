from pydantic import BaseModel

class UserKeysResponse(BaseModel):
    user_id: int
    certificate: str
    public_key: str
    public_key_signature: str | None = None
    elgamal_public_key: str | None = None
    elgamal_public_key_signature: str | None = None
    encrypted_private_key: str
    ed_public_key: str
    ed_encrypted_private_key: str

class DecryptRequest(BaseModel):
    username: str
    password: str

class DecryptedPrivateKeyResponse(BaseModel):
    private_key_pem: str
    elgamal_private_key: int | None = None