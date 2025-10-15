"""
System API endpoints
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db

router = APIRouter()


@router.get("/status")
async def system_status(db: AsyncSession = Depends(get_db)):
    """Get system status and health information"""
    return {
        "status": "healthy",
        "message": "System status endpoint - to be implemented"
    }


@router.get("/metrics") 
async def system_metrics(db: AsyncSession = Depends(get_db)):
    """Get system metrics"""
    return {"message": "System metrics endpoint - to be implemented"}
