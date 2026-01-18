from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app import models, schemas
from app.database import get_db
from app.services import intelligence

router = APIRouter(prefix="/roles", tags=["roles"])

@router.get("/", response_model=List[schemas.JobRole])
def list_roles(db: Session = Depends(get_db)):
    return db.query(models.JobRole).all()

@router.get("/recommend/{user_id}", response_model=List[schemas.RoleReadiness])
def get_recommendations(user_id: int, db: Session = Depends(get_db)):
    return intelligence.get_role_recommendations(user_id, db)

@router.get("/{role_id}", response_model=schemas.JobRole)
def get_role(role_id: int, db: Session = Depends(get_db)):
    role = db.query(models.JobRole).filter(models.JobRole.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    return role

@router.post("/simulate", response_model=schemas.SimulationResponse)
def simulate_impact(request: schemas.SimulationRequest, db: Session = Depends(get_db)):
    result = intelligence.simulate_readiness(request, db)
    if not result:
        raise HTTPException(status_code=404, detail="Entity not found")
    return result

