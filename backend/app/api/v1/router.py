"""
Main API router for version 1
"""

from fastapi import APIRouter
from app.api.v1.endpoints import (
    auth,
    users, 
    labs,
    sessions,
    progress,
    admin,
    system
)
from app.api.v1 import vpn

# Create main API router
api_router = APIRouter()

# Include endpoint routers
api_router.include_router(
    auth.router, 
    prefix="/auth", 
    tags=["Authentication"]
)

api_router.include_router(
    users.router, 
    prefix="/users", 
    tags=["Users"]
)

api_router.include_router(
    labs.router, 
    prefix="/labs", 
    tags=["Labs"]
)

api_router.include_router(
    sessions.router, 
    prefix="/sessions", 
    tags=["Lab Sessions"]
)

api_router.include_router(
    progress.router, 
    prefix="/progress", 
    tags=["User Progress"]
)

api_router.include_router(
    admin.router, 
    prefix="/admin", 
    tags=["Administration"]
)

api_router.include_router(
    system.router, 
    prefix="/system", 
    tags=["System"]
)

api_router.include_router(
    vpn.router, 
    prefix="/vpn", 
    tags=["VPN"]
)
