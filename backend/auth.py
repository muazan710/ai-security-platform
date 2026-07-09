# auth.py - Complete Production-Ready Authentication System

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from datetime import datetime, timedelta

import secrets
import json
import re
import hashlib

from database import get_db
from models import User, AuditLog

from schemas import (
    UserSignup,
    UserLogin,
    SignupResponse,
    TokenResponse,
    VerifyOTPRequest,
    ResendOTPRequest,
    ForgotPasswordRequest,
    VerifyResetOTPRequest,
    ResetPasswordRequest,
    MessageResponse,
)

from security import (
    hash_password,
    verify_password,
    create_access_token,
    generate_api_key,
    get_current_user_from_jwt,
)

from email_service import send_otp_email


# ==============================
# ROUTER
# ==============================

router = APIRouter(
    tags=["Authentication"]
)


# ==============================
# UTILITY FUNCTIONS
# ==============================

def generate_otp():
    """Generate 6-digit OTP"""
    return str(secrets.randbelow(900000) + 100000)


def hash_otp(otp: str) -> str:
    """Hash OTP for secure storage"""
    return hashlib.sha256(otp.encode()).hexdigest()


def verify_otp(otp: str, hashed_otp: str) -> bool:
    """Verify OTP against hashed version"""
    return hashlib.sha256(otp.encode()).hexdigest() == hashed_otp


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
    
    # Generate OTP
    otp = generate_otp()
    otp_expiry = datetime.utcnow() + timedelta(minutes=10)
    
    # Generate API Key
    raw_api_key, api_hash, api_prefix = generate_api_key()
    
    # Create user
    new_user = User(
        email=user.email,
        password_hash=hash_password(user.password),
        api_key_hash=api_hash,
        api_key_prefix=api_prefix,
        email_verified=False,
        email_otp=hash_otp(otp),  # Store hashed OTP
        otp_expiry=otp_expiry,
        otp_attempts=0,
        is_active=True,
        failed_login_attempts=0,
        lock_until=None,
        last_otp_sent=datetime.utcnow()
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Create audit log
    create_audit_log(db, new_user.id, "SIGNUP", f"User registered with email {user.email}")
    
    # Send OTP email
    try:
        send_otp_email(user.email, otp)
    except Exception as e:
        print(f"Email sending error: {e}")
    
    return {
        "message": "Account created successfully. Please verify your email.",
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
    
    # Check email verification
    if not existing.email_verified:
        raise HTTPException(
            status_code=403,
            detail="Please verify your email before logging in."
        )
    
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
        "verified": current_user.email_verified,
        "usage_count": current_user.usage_count,
        "created_at": current_user.created_at,
        "last_login": current_user.last_login,
        "api_key_prefix": current_user.api_key_prefix,
    }


# ==============================
# PART 2 - EMAIL VERIFICATION
# ==============================

@router.post("/verify-email", response_model=MessageResponse)
def verify_email(data: VerifyOTPRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    
    if not user:
        raise HTTPException(404, "User not found")
    
    if user.email_verified:
        return {"message": "Email already verified."}
    
    if user.email_otp is None:
        raise HTTPException(400, "No OTP found.")
    
    if user.otp_expiry is None or datetime.utcnow() > user.otp_expiry:
        raise HTTPException(400, "OTP expired.")
    
    if user.otp_attempts >= 5:
        raise HTTPException(400, "Maximum OTP attempts reached.")
    
    # Verify hashed OTP
    if not verify_otp(data.otp, user.email_otp):
        user.otp_attempts += 1
        db.commit()
        raise HTTPException(400, "Invalid OTP")
    
    # Mark email as verified
    user.email_verified = True
    user.email_otp = None
    user.otp_expiry = None
    user.otp_attempts = 0
    
    db.commit()
    
    # Create audit log
    create_audit_log(db, user.id, "VERIFY_EMAIL", "Email verified successfully")
    
    return {"message": "Email verified successfully."}


@router.post("/resend-otp", response_model=MessageResponse)
def resend_otp(data: ResendOTPRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    
    if not user:
        raise HTTPException(404, "User not found")
    
    if user.email_verified:
        return {"message": "Email already verified."}
    
    # Check cooldown (60 seconds)
    if (user.last_otp_sent and 
        datetime.utcnow() - user.last_otp_sent < timedelta(seconds=60)):
        remaining = 60 - (datetime.utcnow() - user.last_otp_sent).seconds
        raise HTTPException(
            429,
            f"Please wait {remaining} seconds before requesting another OTP."
        )
    
    # Generate and send new OTP
    otp = generate_otp()
    user.email_otp = hash_otp(otp)
    user.otp_expiry = datetime.utcnow() + timedelta(minutes=10)
    user.otp_attempts = 0
    user.last_otp_sent = datetime.utcnow()
    
    db.commit()
    
    try:
        send_otp_email(user.email, otp)
    except Exception as e:
        print(f"Email sending error: {e}")
        raise HTTPException(500, "Unable to send OTP.")
    
    return {"message": "OTP sent successfully."}


# ==============================
# PART 3 - FORGOT PASSWORD
# ==============================

@router.post("/forgot-password", response_model=MessageResponse)
def forgot_password(data: ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    
    if not user:
        raise HTTPException(404, "Email not found")
    
    # Check cooldown (60 seconds)
    if (user.last_otp_sent and 
        datetime.utcnow() - user.last_otp_sent < timedelta(seconds=60)):
        remaining = 60 - (datetime.utcnow() - user.last_otp_sent).seconds
        raise HTTPException(
            429,
            f"Please wait {remaining} seconds before requesting another OTP."
        )
    
    # Generate and send OTP
    otp = generate_otp()
    user.email_otp = hash_otp(otp)
    user.otp_expiry = datetime.utcnow() + timedelta(minutes=10)
    user.otp_attempts = 0
    user.last_otp_sent = datetime.utcnow()
    
    db.commit()
    
    try:
        send_otp_email(user.email, otp)
    except Exception as e:
        print(f"Email sending error: {e}")
        raise HTTPException(500, "Unable to send OTP")
    
    # Create audit log
    create_audit_log(db, user.id, "FORGOT_PASSWORD", "Password reset OTP requested")
    
    return {"message": "Password reset OTP sent successfully."}


@router.post("/verify-reset-otp", response_model=MessageResponse)
def verify_reset_otp(data: VerifyResetOTPRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    
    if not user:
        raise HTTPException(404, "User not found")
    
    if user.email_otp is None:
        raise HTTPException(400, "OTP not found")
    
    if user.otp_expiry is None or datetime.utcnow() > user.otp_expiry:
        raise HTTPException(400, "OTP expired")
    
    if user.otp_attempts >= 5:
        raise HTTPException(400, "Maximum attempts exceeded")
    
    # Verify hashed OTP
    if not verify_otp(data.otp, user.email_otp):
        user.otp_attempts += 1
        db.commit()
        raise HTTPException(400, "Invalid OTP")
    
    # Reset attempts but keep OTP for reset password
    user.otp_attempts = 0
    db.commit()
    
    return {"message": "OTP verified successfully."}


@router.post("/reset-password", response_model=MessageResponse)
def reset_password(data: ResetPasswordRequest, db: Session = Depends(get_db)):
    # Validate new password
    validate_password(data.new_password)
    
    user = db.query(User).filter(User.email == data.email).first()
    
    if not user:
        raise HTTPException(404, "User not found")
    
    # Verify OTP
    if user.email_otp is None:
        raise HTTPException(400, "No OTP found. Please request a new one.")
    
    if user.otp_expiry is None or datetime.utcnow() > user.otp_expiry:
        raise HTTPException(400, "OTP expired. Please request a new one.")
    
    if not verify_otp(data.otp, user.email_otp):
        user.otp_attempts += 1
        db.commit()
        raise HTTPException(400, "Invalid OTP")
    
    # Update password
    user.password_hash = hash_password(data.new_password)
    user.email_otp = None
    user.otp_expiry = None
    user.otp_attempts = 0
    
    db.commit()
    
    # Create audit log
    create_audit_log(db, user.id, "RESET_PASSWORD", "Password reset successfully")
    
    return {"message": "Password changed successfully."}


@router.post("/resend-reset-otp", response_model=MessageResponse)
def resend_reset_otp(data: ResendOTPRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    
    if not user:
        raise HTTPException(404, "User not found")
    
    # Check cooldown (60 seconds)
    if (user.last_otp_sent and 
        datetime.utcnow() - user.last_otp_sent < timedelta(seconds=60)):
        remaining = 60 - (datetime.utcnow() - user.last_otp_sent).seconds
        raise HTTPException(
            429,
            f"Please wait {remaining} seconds before requesting another OTP."
        )
    
    # Generate and send new OTP
    otp = generate_otp()
    user.email_otp = hash_otp(otp)
    user.otp_expiry = datetime.utcnow() + timedelta(minutes=10)
    user.otp_attempts = 0
    user.last_otp_sent = datetime.utcnow()
    
    db.commit()
    
    try:
        send_otp_email(user.email, otp)
    except Exception as e:
        print(f"Email sending error: {e}")
        raise HTTPException(500, "Unable to send OTP")
    
    return {"message": "OTP sent successfully."}


# ==============================
# PART 4 - API KEY MANAGEMENT
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