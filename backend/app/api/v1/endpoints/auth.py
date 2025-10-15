"""
Authentication API endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta
from typing import Optional
import uuid

from app.core.database import get_db
from app.core.redis import redis_client, cache_user_session
from app.models.user import User
from app.models.system import AuditLog, AuditEventType
from app.schemas.auth import (
    UserLogin, 
    UserRegister, 
    Token, 
    TokenRefresh,
    UserResponse
)
from app.core.security import (
    create_access_token,
    create_refresh_token,
    verify_password,
    get_password_hash,
    verify_token
)
from app.services.user_service import UserService
from app.services.audit_service import AuditService

router = APIRouter()
security = HTTPBearer()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserRegister,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """Register a new user"""
    
    user_service = UserService(db)
    audit_service = AuditService(db)
    
    # Check if user already exists
    existing_user = await user_service.get_by_username(user_data.username)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    existing_email = await user_service.get_by_email(user_data.email)
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create new user
    password_hash = get_password_hash(user_data.password)
    
    user = User(
        id=uuid.uuid4(),
        username=user_data.username,
        email=user_data.email,
        password_hash=password_hash,
        first_name=user_data.first_name,
        last_name=user_data.last_name
    )
    
    created_user = await user_service.create(user)
    
    # Log registration event
    await audit_service.log_event(
        event_type=AuditEventType.USER_LOGIN,
        message=f"User registered: {user_data.username}",
        user_id=created_user.id,
        username=user_data.username,
        ip_address=request.client.host,
        event_data={
            "registration_method": "email",
            "user_agent": request.headers.get("user-agent")
        }
    )
    
    return UserResponse.from_orm(created_user)


@router.post("/login", response_model=Token)
async def login(
    credentials: UserLogin,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """Authenticate user and return JWT tokens"""
    
    user_service = UserService(db)
    audit_service = AuditService(db)
    
    # Get user by username or email
    user = await user_service.get_by_username(credentials.username)
    if not user:
        user = await user_service.get_by_email(credentials.username)
    
    # Verify credentials
    if not user or not verify_password(credentials.password, user.password_hash):
        # Log failed login attempt
        await audit_service.log_event(
            event_type=AuditEventType.USER_LOGIN,
            message=f"Failed login attempt: {credentials.username}",
            username=credentials.username,
            ip_address=request.client.host,
            event_data={
                "success": False,
                "reason": "invalid_credentials"
            }
        )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username/email or password"
        )
    
    # Check if user is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is disabled"
        )
    
    # Create JWT tokens
    access_token = create_access_token({"sub": str(user.id), "username": user.username})
    refresh_token = create_refresh_token({"sub": str(user.id)})
    
    # Update user's last login
    user.last_login = datetime.utcnow()
    await user_service.update(user)
    
    # Cache user session
    session_data = {
        "user_id": str(user.id),
        "username": user.username,
        "is_admin": user.is_admin,
        "subscription_tier": user.subscription_tier,
        "login_time": datetime.utcnow().isoformat()
    }
    await cache_user_session(str(user.id), session_data, expire_seconds=3600)
    
    # Log successful login
    await audit_service.log_event(
        event_type=AuditEventType.USER_LOGIN,
        message=f"User logged in: {user.username}",
        user_id=user.id,
        username=user.username,
        ip_address=request.client.host,
        event_data={
            "success": True,
            "login_method": "password",
            "user_agent": request.headers.get("user-agent")
        }
    )
    
    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        user=UserResponse.from_orm(user)
    )


@router.post("/refresh", response_model=Token)
async def refresh_token(
    token_data: TokenRefresh,
    db: AsyncSession = Depends(get_db)
):
    """Refresh JWT access token"""
    
    user_service = UserService(db)
    
    # Verify refresh token
    try:
        payload = verify_token(token_data.refresh_token)
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    # Get user
    user = await user_service.get_by_id(uuid.UUID(user_id))
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    
    # Create new tokens
    access_token = create_access_token({"sub": str(user.id), "username": user.username})
    new_refresh_token = create_refresh_token({"sub": str(user.id)})
    
    return Token(
        access_token=access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
        user=UserResponse.from_orm(user)
    )


@router.post("/logout")
async def logout(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
):
    """Logout user and invalidate tokens"""
    
    audit_service = AuditService(db)
    
    try:
        # Verify and decode token
        payload = verify_token(credentials.credentials)
        user_id = payload.get("sub")
        username = payload.get("username")
        
        if user_id:
            # Remove cached session
            await redis_client.delete(f"user_session:{user_id}")
            
            # Log logout event
            await audit_service.log_event(
                event_type=AuditEventType.USER_LOGOUT,
                message=f"User logged out: {username}",
                user_id=uuid.UUID(user_id) if user_id else None,
                username=username,
                ip_address=request.client.host
            )
    
    except Exception:
        # Token might be invalid, but that's okay for logout
        pass
    
    return {"message": "Successfully logged out"}


@router.get("/me", response_model=UserResponse)
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
):
    """Get current authenticated user information"""
    
    user_service = UserService(db)
    
    try:
        # Verify token
        payload = verify_token(credentials.credentials)
        user_id = payload.get("sub")
        
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        # Get user
        user = await user_service.get_by_id(uuid.UUID(user_id))
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
        
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is disabled"
            )
        
        return UserResponse.from_orm(user)
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )


@router.post("/verify-token")
async def verify_access_token(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Verify if access token is valid"""
    
    try:
        payload = verify_token(credentials.credentials)
        return {
            "valid": True,
            "user_id": payload.get("sub"),
            "username": payload.get("username"),
            "expires_at": payload.get("exp")
        }
    except Exception:
        return {"valid": False}


# Dependency for getting current user
async def get_current_user_dependency(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """Dependency to get current authenticated user"""
    
    user_service = UserService(db)
    
    try:
        payload = verify_token(credentials.credentials)
        user_id = payload.get("sub")
        
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        user = await user_service.get_by_id(uuid.UUID(user_id))
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
        
        return user
    
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )
