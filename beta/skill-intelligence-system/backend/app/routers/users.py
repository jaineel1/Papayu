from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app import models, schemas
from app.database import get_db

router = APIRouter(prefix="/users", tags=["users"])

@router.post("/", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = models.User(
        full_name=user.full_name, 
        email=user.email,
        current_role_title=user.current_role_title
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@router.get("/{user_id}", response_model=schemas.User)
def read_user(user_id: int, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user

@router.get("/by-email/{email}", response_model=schemas.User)
def read_user_by_email(email: str, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == email).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user

@router.put("/{user_id}", response_model=schemas.User)
def update_user(user_id: int, user_update: schemas.UserUpdate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user_update.full_name:
        db_user.full_name = user_update.full_name
    if user_update.current_role_title is not None:
        db_user.current_role_title = user_update.current_role_title
    if user_update.target_role_id is not None:
        db_user.target_role_id = user_update.target_role_id
        
    db.commit()
    db.refresh(db_user)
    return db_user

@router.post("/{user_id}/skills", response_model=schemas.UserSkill)
def add_skill_to_user(user_id: int, skill: schemas.UserSkillBase, db: Session = Depends(get_db)):
    # Check if skill exists
    existing_skill = db.query(models.UserSkill).filter(
        models.UserSkill.user_id == user_id,
        models.UserSkill.skill_id == skill.skill_id
    ).first()

    if existing_skill:
        existing_skill.proficiency_level = skill.proficiency_level
        db.commit()
        db.refresh(existing_skill)
        return existing_skill

    user_skill = models.UserSkill(
        user_id=user_id,
        skill_id=skill.skill_id,
        proficiency_level=skill.proficiency_level
    )
    db.add(user_skill)
    db.commit()
    db.refresh(user_skill)
    return user_skill

@router.delete("/{user_id}/skills/{skill_id}")
def delete_user_skill(user_id: int, skill_id: int, db: Session = Depends(get_db)):
    user_skill = db.query(models.UserSkill).filter(
        models.UserSkill.user_id == user_id,
        models.UserSkill.skill_id == skill_id
    ).first()
    
    if not user_skill:
        raise HTTPException(status_code=404, detail="Skill not found for this user")
        
    db.delete(user_skill)
    db.commit()
    return {"message": "Skill removed successfully"}
