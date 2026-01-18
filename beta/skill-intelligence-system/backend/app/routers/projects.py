from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app import models, schemas
from app.database import get_db
from app.services import intelligence

router = APIRouter(prefix="/projects", tags=["projects"])

@router.get("/recommend/{user_id}", response_model=List[schemas.Project])
def recommend_projects(user_id: int, db: Session = Depends(get_db)):
    results = intelligence.get_project_recommendations(user_id, db)
    return results
