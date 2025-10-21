from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routers import register  # Import the auth router module
from .routers import users  # Import the users router module
from .routers import login  # Import the login router module
from .routers import keys # Import the keys router module
from .routers import sessions # Import the sessions router module

# Crea la instancia principal de la aplicación FastAPI
app = FastAPI(
    title="Spy Agency API",
    description="In this API you will find how to interact with the backend, mostly to use cryptography-related functions.",
    version="0.1.0",
)

# --- CORS Configuration ---
# List of allowed origins (your frontend's domains/ports)
origins = [
    "http://localhost:5173",  # Default Vite port
    "http://localhost:3000",  # Default Create React App port
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,       # Allow these origins
    allow_credentials=True,      # Allow cookies (important for the future)
    allow_methods=["*"],         # Allow all methods (GET, POST, etc.)
    allow_headers=["*"],         # Allow all headers
)
# --- End of CORS configuration ---

# Include routers
app.include_router(register.router, prefix="/auth/register", tags=["Authentication"])
app.include_router(login.router, prefix="/auth/login", tags=["Authentication"])
app.include_router(keys.router, prefix="/keys", tags=["Keys"])
app.include_router(sessions.router, prefix="/sessions", tags=["Sessions"])
app.include_router(users.router, prefix="/users", tags=["Users"])


@app.get("/", tags=["Root"])
async def read_root():
    return {"message": "Welcome to the API. Go to /docs for interactive documentation."}