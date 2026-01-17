from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from app import models, schemas, security
from app.database import get_db

router = APIRouter(prefix="/auth", tags=["authentication"])

@router.post("/register", response_model=schemas.User)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = security.get_password_hash(user.password)
    new_user = models.User(
        email=user.email,
        full_name=user.full_name,
        current_role_title=user.current_role_title,
        password_hash=hashed_password
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # SAFETY: Ensure no orphaned skills exist for this new user ID (SQLite reuse edge case)
    print(f"DEBUG: Default cleanup for User ID {new_user.id} starting...")
    deleted_count = db.query(models.UserSkill).filter(models.UserSkill.user_id == new_user.id).delete()
    print(f"DEBUG: CLEANED UP {deleted_count} ORPHANED SKILLS for User ID {new_user.id}")
    db.commit()
    
    # Force reload of relationships to ensure empty skills list
    db.expire(new_user)
    db.refresh(new_user)
    print(f"DEBUG: Final skill count for new user: {len(new_user.skills)}")

    return new_user

@router.post("/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == form_data.username).first()
    if not user or not security.verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=security.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        data={"sub": user.email, "user_id": user.id}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer", "user_id": user.id, "full_name": user.full_name}
