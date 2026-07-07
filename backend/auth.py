from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime
import secrets

from database import get_db
from models import User
from schemas import UserSignup, UserLogin, SignupResponse, TokenResponse
from security import (
    hash_password,
    verify_password,
    create_access_token,
    generate_api_key,
)

router = APIRouter(tags=["Authentication"])


@router.post("/signup", response_model=SignupResponse)
def signup(user: UserSignup, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == user.email).first()

    if existing:
        raise HTTPException(status_code=400, detail="Email already exists")

    raw_api_key, api_hash, api_prefix = generate_api_key()

    new_user = User(
        email=user.email,
        password_hash=hash_password(user.password),
        api_key_hash=api_hash,
        api_key_prefix=api_prefix,
    )

    db.add(new_user)
    db.commit()

    return {
        "message": "User created successfully",
        "api_key": raw_api_key,
    }


@router.post("/login", response_model=TokenResponse)
def login(user: UserLogin, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == user.email).first()

    if not existing:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not verify_password(user.password, existing.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Update last_login timestamp
    existing.last_login = datetime.utcnow()
    db.commit()

    # Generate new API key on each login (Round 2 requirement)
    raw_api_key, api_hash, api_prefix = generate_api_key()
    
    # Update user with new API key
    existing.api_key_hash = api_hash
    existing.api_key_prefix = api_prefix
    db.commit()

    token = create_access_token(
        {
            "sub": existing.email,
        }
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "api_key": raw_api_key,
        "email": existing.email,
        "api_key_prefix": api_prefix,
    }