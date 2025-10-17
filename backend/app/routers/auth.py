from fastapi import APIRouter, HTTPException, status, Body
from fastapi.responses import JSONResponse
from ..schemas import user as user_schema
from ..services import user_service

router = APIRouter()

@router.post("/register")
async def register_user(user_data: user_schema.UserCreate = Body(...)):
    """
    Endpoint de prueba para registrar un nuevo usuario.
    - Recibe un JSON con username, email y password.
    - Si el username es "error", devuelve un error 400.
    - Si no, simula una inserción exitosa y devuelve un 200 OK.
    """
    if user_data.username == "error":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Error simulado al intentar registrar el usuario."
        )
    
    # Obviamos la implementación de insertar el usuario, como se solicitó.
    # Simplemente devolvemos una respuesta de éxito.
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": f"Usuario '{user_data.username}' registrado con éxito (simulación)."}
    )
