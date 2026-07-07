from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import jwt
import secrets
import hashlib
from fastapi import Header, HTTPException, Depends
from sqlalchemy.orm import Session

from database import get_db
from models import User

# ============================================
# CONFIGURATION
# ============================================
SECRET_KEY = "CHANGE_THIS_TO_A_RANDOM_SECRET_KEY"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# ============================================
# PASSWORD HASHING
# ============================================
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)


def hash_password(password: str):
    """Hash a password using bcrypt"""
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str):
    """Verify a password against its hash"""
    return pwd_context.verify(password, hashed)


def create_access_token(data: dict):
    """Create a JWT access token"""
    to_encode = data.copy()
    
    expire = datetime.utcnow() + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )
    
    to_encode.update({"exp": expire})
    
    return jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM
    )


def generate_api_key():
    """Generate a new API key"""
    raw_key = "sk_live_" + secrets.token_urlsafe(32)
    
    key_hash = hashlib.sha256(
        raw_key.encode()
    ).hexdigest()
    
    prefix = raw_key[:12]
    
    return raw_key, key_hash, prefix


# ============================================
# API KEY VERIFICATION
# ============================================
def verify_api_key(
    x_api_key: str = Header(..., alias="X-API-Key"),
    db: Session = Depends(get_db),
):
    """
    Verify API key from request header
    Returns the hashed API key if valid, raises HTTPException if invalid
    """
    key_hash = hashlib.sha256(
        x_api_key.encode()
    ).hexdigest()
    
    user = db.query(User).filter(
        User.api_key_hash == key_hash
    ).first()
    
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid API Key"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="User account is disabled"
        )
    
    return key_hash


def verify_admin_api_key(
    x_api_key: str = Header(..., alias="X-API-Key"),
    db: Session = Depends(get_db),
):
    """
    Verify admin API key - requires admin role
    Returns the hashed API key if valid, raises HTTPException if invalid
    """
    key_hash = hashlib.sha256(
        x_api_key.encode()
    ).hexdigest()
    
    user = db.query(User).filter(
        User.api_key_hash == key_hash
    ).first()
    
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid API Key"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="User account is disabled"
        )
    
    if not user.is_admin:
        raise HTTPException(
            status_code=403,
            detail="Admin privileges required"
        )
    
    return key_hash


def verify_api_key_optional(
    x_api_key: str = Header(None, alias="X-API-Key"),
    db: Session = Depends(get_db),
):
    """
    Optional API key verification - doesn't raise error if key is missing
    Returns the hashed API key if valid, None if missing or invalid
    """
    if x_api_key is None:
        return None
    
    key_hash = hashlib.sha256(
        x_api_key.encode()
    ).hexdigest()
    
    user = db.query(User).filter(
        User.api_key_hash == key_hash
    ).first()
    
    if not user or not user.is_active:
        return None
    
    return key_hash


def get_user_from_api_key(
    x_api_key: str = Header(..., alias="X-API-Key"),
    db: Session = Depends(get_db),
):
    """
    Get user object from API key
    Returns the User object if valid, raises HTTPException if invalid
    """
    key_hash = hashlib.sha256(
        x_api_key.encode()
    ).hexdigest()
    
    user = db.query(User).filter(
        User.api_key_hash == key_hash
    ).first()
    
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid API Key"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="User account is disabled"
        )
    
    return user