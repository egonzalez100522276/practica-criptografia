from fastapi import FastAPI
from .routers import auth  # Importamos el módulo del router de autenticación

# Crea la instancia principal de la aplicación FastAPI
app = FastAPI(
    title="API de la Agencia de Espías",
    description="Una API para gestionar agentes secretos y sus misiones.",
    version="0.1.0",
)

# Incluimos las rutas del router 'auth'.
# El 'prefix' hace que todas las rutas de ese router empiecen por /auth
# (ej: /auth/register)
app.include_router(auth.router, prefix="/auth", tags=["Authentication"])

@app.get("/", tags=["Root"])
async def read_root():
    return {"message": "Bienvenido a la API. Ve a /docs para la documentación interactiva."}