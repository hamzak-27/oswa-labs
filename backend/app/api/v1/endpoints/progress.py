"""
User Progress API endpoints
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.user import User
from app.api.v1.endpoints.auth import get_current_user_dependency

router = APIRouter()


@router.get("/")
async def get_my_progress(
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Get current user's progress across all labs"""
    return {"message": "Progress endpoint - to be implemented"}


@router.post("/submit-flag")
async def submit_flag(
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Submit a flag for validation"""
    return {"message": "Flag submission endpoint - to be implemented"}
