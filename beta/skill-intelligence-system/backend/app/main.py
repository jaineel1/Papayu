from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app import models
from app.database import engine, Base
from app.routers import users, roles

# Create DB tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Skill Intelligence System")

# CORS for React
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allow all for hackathon
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(users.router)
app.include_router(roles.router)
from app.routers import skills, auth
app.include_router(skills.router)
app.include_router(auth.router)

from app.routers import projects
app.include_router(projects.router)

@app.get("/")
def read_root():
    return {"status": "ok", "message": "Intelligence Engine Running"}
