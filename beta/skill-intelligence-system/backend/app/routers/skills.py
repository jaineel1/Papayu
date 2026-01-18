from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List
from app import models, schemas
from app.database import get_db

router = APIRouter(prefix="/skills", tags=["skills"])

@router.get("/", response_model=List[schemas.Skill])
def list_skills(db: Session = Depends(get_db)):
    return db.query(models.Skill).all()

@router.get("/resources", response_model=List[schemas.ResourceRecommendation])
def list_resources(db: Session = Depends(get_db)):
    # Return all resources for the catalogue
    res = db.query(models.LearningResource).all()
    return [
        schemas.ResourceRecommendation(
            title=r.title, type=r.type, provider=r.provider, 
            link=r.link, difficulty_level=r.difficulty_level
        ) for r in res
    ]
