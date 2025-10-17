from pydantic import BaseModel, EmailStr

# Esquema para recibir los datos de registro de un usuario desde el frontend
class UserCreate(BaseModel):
    email: EmailStr
    password: str

# Esquema para devolver los datos de un usuario al frontend (¡sin la contraseña!)
class UserResponse(BaseModel):
    id: int # Suponiendo que la BD asigna un ID numérico
    email: EmailStr

    class Config:
        from_attributes = True # Permite crear el modelo desde un objeto de la BD