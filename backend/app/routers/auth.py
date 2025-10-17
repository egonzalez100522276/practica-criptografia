from fastapi import APIRouter, HTTPException
from ..schemas import user as user_schema
from ..services import user_service

router = APIRouter()

@router.post("/register", response_model=user_schema.UserResponse)
async def register_user(user_data: user_schema.UserCreate):
    """
    Endpoint para registrar un nuevo usuario.
    - Valida que los datos de entrada coincidan con el esquema UserCreate.
    - Llama al servicio de usuario para manejar la lógica de creación.
    - Devuelve una respuesta que coincide con el esquema UserResponse.
    """
    # En un futuro, aquí se podría comprobar si el email ya existe antes de crearlo.
    # Por ejemplo:
    # db_user = user_service.get_user_by_email(email=user_data.email)
    # if db_user:
    #     raise HTTPException(status_code=400, detail="El email ya está registrado.")
    
    return user_service.create_user(user=user_data)