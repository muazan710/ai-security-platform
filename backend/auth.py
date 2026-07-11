# auth.py - Complete Production-Ready Authentication System

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from datetime import datetime, timedelta

import re

from database import get_db
from models import User, AuditLog

from schemas import (
    UserSignup,
    UserLogin,
    SignupResponse,
    TokenResponse,
    MessageResponse,
)

from security import (
    hash_password,
    verify_password,
    create_access_token,
    generate_api_key,
    get_current_user_from_jwt,
)


# ==============================
# ROUTER
# ==============================

router = APIRouter(
    tags=["Authentication"]
)


def validate_password(password: str):
    """Validate password strength"""
    if len(password) < 8:
        raise HTTPException(400, "Password must contain at least 8 characters.")
    
    if not re.search(r"[A-Z]", password):
        raise HTTPException(400, "Password must contain one uppercase letter.")
    
    if not re.search(r"[a-z]", password):
        raise HTTPException(400, "Password must contain one lowercase letter.")
    
    if not re.search(r"\d", password):
        raise HTTPException(400, "Password must contain one number.")
    
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        raise HTTPException(400, "Password must contain one special character.")


def create_audit_log(db: Session, user_id: int, action: str, details: str = None):
    """Create audit log entry"""
    try:
        audit = AuditLog(
            user_id=user_id,
            action=action,
            details=details,
            created_at=datetime.utcnow()
        )
        db.add(audit)
        db.commit()
    except Exception as e:
        print(f"Audit log error: {e}")


# ==============================
# PART 1 - AUTHENTICATION
# ==============================

@router.post("/signup", response_model=SignupResponse)
def signup(user: UserSignup, db: Session = Depends(get_db)):
    # Validate password strength
    validate_password(user.password)
    
    # Check if email exists
    existing = db.query(User).filter(
        User.email == user.email
    ).first()
    
    if existing:
        raise HTTPException(
            status_code=400,
            detail="Email already exists"
        )
    
    # Generate API Key
    raw_api_key, api_hash, api_prefix = generate_api_key()
    
    # Create user
    new_user = User(
        email=user.email,
        password_hash=hash_password(user.password),
        api_key_hash=api_hash,
        api_key_prefix=api_prefix,
        is_active=True,
        failed_login_attempts=0,
        lock_until=None,
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Create audit log
    create_audit_log(db, new_user.id, "SIGNUP", f"User registered with email {user.email}")
    
    return {
        "message": "Account created successfully. You can log in now.",
        "api_key": raw_api_key,
    }


@router.post("/login", response_model=TokenResponse)
def login(user: UserLogin, db: Session = Depends(get_db)):
    existing = db.query(User).filter(
        User.email == user.email
    ).first()
    
    if not existing:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )
    
    # Check if account is locked
    if existing.lock_until and datetime.utcnow() < existing.lock_until:
        raise HTTPException(
            status_code=423,
            detail="Account temporarily locked. Please try again later."
        )
    
    # Verify password
    if not verify_password(user.password, existing.password_hash):
        # Increment failed attempts
        existing.failed_login_attempts += 1
        
        # Lock account after 5 failed attempts
        if existing.failed_login_attempts >= 5:
            existing.lock_until = datetime.utcnow() + timedelta(minutes=15)
            db.commit()
            raise HTTPException(
                status_code=423,
                detail="Too many failed attempts. Account locked for 15 minutes."
            )
        
        db.commit()
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )
    
    # Reset failed attempts on successful login
    existing.failed_login_attempts = 0
    existing.lock_until = None
    
    if not existing.is_active:
        raise HTTPException(
            status_code=403,
            detail="Account disabled"
        )
    
    # Update last login
    existing.last_login = datetime.utcnow()
    
    # Generate new API Key
    raw_api_key, api_hash, api_prefix = generate_api_key()
    existing.api_key_hash = api_hash
    existing.api_key_prefix = api_prefix
    existing.api_key_created_at = datetime.utcnow()
    
    db.commit()
    
    # Create audit log
    create_audit_log(db, existing.id, "LOGIN", "Successful login")
    
    # Generate JWT with enhanced claims
    token = create_access_token({
        "sub": existing.email,
        "user_id": existing.id,
        "role": existing.role.value if hasattr(existing, 'role') else "user"
    })
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "api_key": raw_api_key,
        "email": existing.email,
        "api_key_prefix": api_prefix,
    }


@router.get("/me")
def me(current_user: User = Depends(get_current_user_from_jwt)):
    return {
        "email": current_user.email,
        "usage_count": current_user.usage_count,
        "created_at": current_user.created_at,
        "last_login": current_user.last_login,
        "api_key_prefix": current_user.api_key_prefix,
    }


# ==============================
# PART 2 - API KEY MANAGEMENT
# ==============================

@router.post("/regenerate-api-key", response_model=MessageResponse)
def regenerate_api_key(
    current_user: User = Depends(get_current_user_from_jwt),
    db: Session = Depends(get_db)
):
    # Generate new API Key
    raw_api_key, api_hash, api_prefix = generate_api_key()
    
    current_user.api_key_hash = api_hash
    current_user.api_key_prefix = api_prefix
    current_user.api_key_created_at = datetime.utcnow()
    
    db.commit()
    
    # Create audit log
    create_audit_log(
        db, 
        current_user.id, 
        "REGENERATE_API_KEY", 
        f"API key regenerated with prefix {api_prefix}"
    )
    
    return {
        "message": "API key regenerated successfully.",
        "api_key": raw_api_key,
        "api_key_prefix": api_prefix
    }
