from pydantic import BaseModel, Field

# Defiine JSON structure for missions
class MissionContent(BaseModel):
    title: str = Field(..., min_length=3, max_length=100)
    description: str = Field(max_length=2000)

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

class MissionDecryptRequest(BaseModel):
    password: str