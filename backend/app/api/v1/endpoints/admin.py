"""
Admin API endpoints
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.user import User
from app.api.v1.endpoints.auth import get_current_user_dependency

router = APIRouter()


@router.get("/dashboard")
async def admin_dashboard(
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Get admin dashboard data"""
    return {"message": "Admin dashboard endpoint - to be implemented"}


@router.get("/users")
async def admin_get_users(
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Get all users (admin only)"""
    return {"message": "Admin users endpoint - to be implemented"}
