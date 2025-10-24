from pydantic import BaseModel

class Token(BaseModel):
    """Standard token response."""
    access_token: str
    token_type: str

class LoginResponse(Token):
    """Response for login/register, including the encrypted private key."""
    encrypted_private_key: str