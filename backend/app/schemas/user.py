from pydantic import BaseModel, EmailStr

# Schema for receiving user registration data from the frontend
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

# Schema for returning user data to the frontend (without the password!)
class UserResponse(BaseModel):
    id: int # Assuming the DB assigns a numeric ID
    username: str
    email: EmailStr

    class Config:
        from_attributes = True # Allows creating the model from a DB object
    
class UserResponseWithPassword(UserResponse):
    password_hash: str

class Token(BaseModel):
    access_token: str
    token_type: str
