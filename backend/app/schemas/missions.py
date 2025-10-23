from pydantic import BaseModel

class MissionCreate(BaseModel):
    content: str # The frontend will send the raw content

class MissionResponse(MissionCreate):
    id: int
    creator_id: int