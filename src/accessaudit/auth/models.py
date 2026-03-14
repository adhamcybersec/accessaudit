"""Authentication Pydantic models."""

from pydantic import BaseModel, EmailStr


class UserCreate(BaseModel):
    """Request body for user registration."""

    email: EmailStr
    password: str


class UserLogin(BaseModel):
    """Request body for user login."""

    email: EmailStr
    password: str


class UserResponse(BaseModel):
    """Public user response."""

    id: str
    email: str
    api_key: str
    is_active: bool


class TokenResponse(BaseModel):
    """JWT token response."""

    access_token: str
    token_type: str = "bearer"
    api_key: str
