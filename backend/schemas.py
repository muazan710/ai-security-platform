from pydantic import BaseModel, EmailStr, Field


class UserSignup(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    full_name: str | None = Field(default=None, max_length=120)


class UserLogin(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=128)


class SignupResponse(BaseModel):
    message: str
    api_key: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    api_key: str
    email: EmailStr
    api_key_prefix: str


class MessageResponse(BaseModel):
    message: str
    api_key: str | None = None
    api_key_prefix: str | None = None
