"""
Users API endpoints
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.user import User
from app.api.v1.endpoints.auth import get_current_user_dependency

router = APIRouter()


@router.get("/profile")
async def get_profile(
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Get current user's profile"""
    return {"message": "User profile endpoint - to be implemented"}


@router.put("/profile")
async def update_profile(
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Update current user's profile"""
    return {"message": "Update profile endpoint - to be implemented"}
