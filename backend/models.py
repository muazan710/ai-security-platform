"""
Database models for AI Security Intelligence Platform
"""
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Enum, Text, Float, ForeignKey
from datetime import datetime
from database import Base
import enum


class UserRole(str, enum.Enum):
    USER = "user"
    ADMIN = "admin"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    
    # API Key fields
    api_key_hash = Column(String, nullable=False)
    api_key_prefix = Column(String, nullable=False)
    api_key_created_at = Column(DateTime, default=datetime.utcnow)
    
    # User status and role
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    role = Column(Enum(UserRole), default=UserRole.USER)
    
    # Usage tracking
    usage_count = Column(Integer, default=0)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

    # Relationships
    # predictions = relationship("PredictionHistory", back_populates="user")
    # audit_logs = relationship("AuditLog", back_populates="user")


class PredictionHistory(Base):
    __tablename__ = "prediction_history"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    url = Column(Text, nullable=False)
    prediction = Column(String, nullable=False)
    confidence = Column(Float, nullable=False)
    risk_level = Column(String, nullable=False)
    model_name = Column(String, nullable=False)
    
    # Feature summary (stored as JSON string)
    feature_summary = Column(Text, nullable=True)
    
    # Result details
    domain_age = Column(Integer, nullable=True)
    domain_exists = Column(Boolean, default=True)
    rule_override = Column(Boolean, default=False)
    risk_factors = Column(Text, nullable=True)  # Store as JSON string
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    # model_results = relationship("PredictionModelResult", back_populates="history")


class PredictionModelResult(Base):
    __tablename__ = "prediction_model_results"

    id = Column(Integer, primary_key=True, index=True)
    
    history_id = Column(Integer, ForeignKey("prediction_history.id"), nullable=False)
    
    model_name = Column(String, nullable=False)
    prediction = Column(String, nullable=False)
    confidence = Column(Float, nullable=False)
    
    feature_summary = Column(Text, nullable=True)
    domain_age = Column(Integer, nullable=True)
    domain_exists = Column(Boolean, default=True)
    rule_override = Column(Boolean, default=False)
    risk_factors = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    # history = relationship("PredictionHistory", back_populates="model_results")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    action = Column(String, nullable=False)
    details = Column(Text, nullable=True)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)


class APIKeyLog(Base):
    __tablename__ = "api_key_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    action = Column(String, nullable=False)  # 'created', 'revoked', 'used'
    api_key_hash = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)