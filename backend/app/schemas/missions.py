from pydantic import BaseModel, Field

# Defiine JSON structure for missions
class MissionContent(BaseModel):
    title: str = Field(..., min_length=3, max_length=100)
    description: str = Field(max_length=2000)
    # signature: str = None

class MissionCreate(BaseModel):
    content: MissionContent

class MissionInDB(BaseModel):
    id: int
    creator_id: int
    content_encrypted: str
    iv: str

class MissionResponse(MissionCreate):
    id: int
    creator_id: int
    creator_username: str | None = None

class MissionDecryptRequest(BaseModel):
    password: str

class MissionDecryptWithKeyRequest(BaseModel):
    private_key_pem: str

class MissionShareRequest(BaseModel):
    user_ids: list[int]
    private_key_pem: str