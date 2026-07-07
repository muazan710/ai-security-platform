from pydantic import BaseModel, EmailStr
from typing import Optional


class UserSignup(BaseModel):
    email: EmailStr
    password: str
    full_name: Optional[str] = None


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class SignupResponse(BaseModel):
    message: str
    api_key: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    api_key: str
    email: str
    api_key_prefix: str