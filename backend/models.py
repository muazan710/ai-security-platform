"""
Database models for AI Security Intelligence Platform.
"""
from datetime import datetime
import enum

from sqlalchemy import Boolean, Column, DateTime, Enum, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import relationship

from database import Base


class UserRole(str, enum.Enum):
    USER = "user"
    ADMIN = "admin"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)

    api_key_hash = Column(String, nullable=False, index=True)
    api_key_prefix = Column(String, nullable=False)
    api_key_created_at = Column(DateTime, default=datetime.utcnow)

    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    role = Column(Enum(UserRole), default=UserRole.USER)

    usage_count = Column(Integer, default=0)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

    email_verified = Column(Boolean, default=False)
    email_otp = Column(String, nullable=True)
    otp_expiry = Column(DateTime, nullable=True)
    otp_attempts = Column(Integer, default=0)
    last_otp_sent = Column(DateTime, nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    lock_until = Column(DateTime, nullable=True)

    predictions = relationship("PredictionHistory", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")
    api_key_logs = relationship("APIKeyLog", back_populates="user", cascade="all, delete-orphan")


class PredictionHistory(Base):
    __tablename__ = "prediction_history"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    url = Column(Text, nullable=False)

    prediction = Column(String, nullable=False)
    confidence = Column(Float, nullable=False)
    risk_level = Column(String, nullable=False)

    ai_agent = Column(Text, nullable=True)
    virustotal = Column(Text, nullable=True)
    threat_intelligence = Column(Text, nullable=True)
    feature_summary = Column(Text, nullable=True)

    domain_age = Column(Integer, nullable=True)
    domain_exists = Column(Boolean, default=True)
    rule_override = Column(Boolean, default=False)
    risk_factors = Column(Text, nullable=True)
    risk_score = Column(Integer, nullable=True)
    scan_duration = Column(Float, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="predictions")
    model_results = relationship("PredictionModelResult", back_populates="history", cascade="all, delete-orphan")


class PredictionModelResult(Base):
    __tablename__ = "prediction_model_results"

    id = Column(Integer, primary_key=True, index=True)
    history_id = Column(Integer, ForeignKey("prediction_history.id", ondelete="CASCADE"), nullable=False, index=True)

    model_name = Column(String, nullable=False)
    prediction = Column(String, nullable=False)
    confidence = Column(Float, nullable=False)
    execution_time = Column(Float, nullable=True)

    feature_summary = Column(Text, nullable=True)
    domain_age = Column(Integer, nullable=True)
    domain_exists = Column(Boolean, default=True)
    rule_override = Column(Boolean, default=False)
    risk_factors = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    history = relationship("PredictionHistory", back_populates="model_results")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    action = Column(String, nullable=False)
    details = Column(Text, nullable=True)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="audit_logs")


class APIKeyLog(Base):
    __tablename__ = "api_key_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    action = Column(String, nullable=False)
    api_key_hash = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="api_key_logs")


Index("ix_prediction_history_user_created", PredictionHistory.user_id, PredictionHistory.created_at)
Index("ix_prediction_model_results_history_model", PredictionModelResult.history_id, PredictionModelResult.model_name)
Index("ix_audit_logs_user_created", AuditLog.user_id, AuditLog.created_at)
