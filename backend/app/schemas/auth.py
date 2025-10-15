"""
Authentication schemas for request/response validation
"""

from pydantic import BaseModel, EmailStr, validator
from typing import Optional
from datetime import datetime
import uuid

from app.core.security import validate_password_strength


class UserLogin(BaseModel):
    """User login request schema"""
    username: str  # Can be username or email
    password: str
    
    class Config:
        json_schema_extra = {
            "example": {
                "username": "john_doe",
                "password": "SecurePassword123!"
            }
        }


class UserRegister(BaseModel):
    """User registration request schema"""
    username: str
    email: EmailStr
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    
    @validator("username")
    def validate_username(cls, v):
        if len(v) < 3:
            raise ValueError("Username must be at least 3 characters long")
        if len(v) > 50:
            raise ValueError("Username must be less than 50 characters")
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError("Username can only contain letters, numbers, underscores, and hyphens")
        return v.lower()
    
    @validator("password")
    def validate_password(cls, v):
        is_valid, message = validate_password_strength(v)
        if not is_valid:
            raise ValueError(message)
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "username": "john_doe",
                "email": "john@example.com",
                "password": "SecurePassword123!",
                "first_name": "John",
                "last_name": "Doe"
            }
        }


class TokenRefresh(BaseModel):
    """Token refresh request schema"""
    refresh_token: str


class UserResponse(BaseModel):
    """User response schema"""
    id: uuid.UUID
    username: str
    email: str
    first_name: Optional[str]
    last_name: Optional[str]
    full_name: str
    is_active: bool
    is_verified: bool
    is_admin: bool
    subscription_tier: str
    max_concurrent_sessions: int
    created_at: datetime
    last_login: Optional[datetime]
    
    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "username": "john_doe",
                "email": "john@example.com",
                "first_name": "John",
                "last_name": "Doe",
                "full_name": "John Doe",
                "is_active": True,
                "is_verified": True,
                "is_admin": False,
                "subscription_tier": "free",
                "max_concurrent_sessions": 1,
                "created_at": "2023-12-01T10:00:00Z",
                "last_login": "2023-12-01T10:00:00Z"
            }
        }


class Token(BaseModel):
    """JWT token response schema"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 1800  # 30 minutes in seconds
    user: UserResponse
    
    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "expires_in": 1800,
                "user": {
                    "id": "123e4567-e89b-12d3-a456-426614174000",
                    "username": "john_doe",
                    "email": "john@example.com"
                }
            }
        }


class PasswordReset(BaseModel):
    """Password reset request schema"""
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    """Password reset confirmation schema"""
    token: str
    new_password: str
    
    @validator("new_password")
    def validate_password(cls, v):
        is_valid, message = validate_password_strength(v)
        if not is_valid:
            raise ValueError(message)
        return v


class ChangePassword(BaseModel):
    """Change password request schema"""
    current_password: str
    new_password: str
    
    @validator("new_password")
    def validate_password(cls, v):
        is_valid, message = validate_password_strength(v)
        if not is_valid:
            raise ValueError(message)
        return v


class EmailVerification(BaseModel):
    """Email verification request schema"""
    token: str


class APIResponse(BaseModel):
    """Generic API response schema"""
    success: bool
    message: str
    data: Optional[dict] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "success": True,
                "message": "Operation completed successfully",
                "data": {}
            }
        }
