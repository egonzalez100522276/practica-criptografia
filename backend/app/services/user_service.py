from ..schemas import user as user_schema
from ..core.security import get_password_hash

def create_user(user: user_schema.UserCreate) -> dict:
    """
    Esta función se encarga de la lógica para crear un usuario.
    1. Hashea la contraseña.
    2. Guarda el usuario en la base de datos (simulado).
    3. Devuelve el usuario creado.
    """
    hashed_password = get_password_hash(user.password)
    
    print("\n--- Simulación de Creación de Usuario en BD ---")
    print(f"Email a guardar: {user.email}")
    print(f"Contraseña hasheada a guardar: {hashed_password}")
    print("--- Fin Simulación ---\n")
    
    # En un caso real, aquí guardarías el usuario en tu BD y obtendrías un ID.
    # Devolvemos un usuario simulado para que coincida con el esquema UserResponse.
    return {"id": 1, "email": user.email}