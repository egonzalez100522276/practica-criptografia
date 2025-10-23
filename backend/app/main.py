from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routers import missions
from .routers import register  
from .routers import users
from .routers import login 
from .routers import keys
from .routers import sessions

# Create main instance of the FastAPI app
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
app.include_router(missions.router, prefix="/missions", tags=["Missions"])


@app.get("/", tags=["Root"])
async def read_root():
    return {"message": "Welcome to the API. Go to /docs for interactive documentation."}