from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routers import auth  # Importamos el módulo del router de autenticación

# Crea la instancia principal de la aplicación FastAPI
app = FastAPI(
    title="Spy Agency API",
    description="In this API you will find how to interact with the backend, mostly to use cryptography-related functions.",
    version="0.1.0",
)

# --- Configuración de CORS ---
# Lista de orígenes permitidos (los dominios/puertos de tu frontend)
origins = [
    "http://localhost:5173",  # El puerto por defecto de Vite
    "http://localhost:3000",  # El puerto por defecto de Create React App
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,       # Permite estos orígenes
    allow_credentials=True,      # Permite cookies (importante para el futuro)
    allow_methods=["*"],         # Permite todos los métodos (GET, POST, etc.)
    allow_headers=["*"],         # Permite todas las cabeceras
)
# --- Fin de la configuración de CORS ---

# Incluimos las rutas del router 'auth'.
# El 'prefix' hace que todas las rutas de ese router empiecen por /auth
# (ej: /auth/register)
app.include_router(auth.router, prefix="/auth", tags=["Authentication"])

@app.get("/", tags=["Root"])
async def read_root():
    return {"message": "Bienvenido a la API. Ve a /docs para la documentación interactiva."}