from pydantic import BaseModel, Field, field_validator
from pydantic_core import PydanticCustomError

# Defiine JSON structure for missions
class MissionContent(BaseModel):
    title: str = Field(..., min_length=3, max_length=100)
    description: str = Field(max_length=2000)

    # Custom error message for frontend.
    @field_validator("title", mode="before")
    def validate_title_length(cls, v):
        if not isinstance(v, str) or len(v) < 3:
            raise PydanticCustomError(
                'title_too_short',
                "Title must be at least 3 characters long.",
            )
        return v

class MissionCreate(BaseModel):
    content: MissionContent
    password: str

class MissionInDB(BaseModel):
    id: int
    content_encrypted: str
    iv: str
    signature: str
    creator_id: int

class MissionResponse(BaseModel):
    id: int
    content: MissionContent
    signature: str
    creator_id: int
    creator_username: str | None = None

class MissionDecryptRequest(BaseModel):
    password: str

class MissionDecryptWithKeyRequest(BaseModel):
    private_key_pem: str

class MissionShareRequest(BaseModel):
    user_ids: list[int]
    private_key_pem: str