"""
Lab Sessions API endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
import uuid

from app.core.database import get_db
from app.models.user import User
from app.api.v1.endpoints.auth import get_current_user_dependency
from app.services.session_service import SessionService
from app.services.network_service import NetworkService
from app.schemas.session import (
    SessionListResponse,
    SessionDetailResponse,
    SessionSummaryResponse,
    ExtendSessionRequest
)

router = APIRouter()


@router.get("/", response_model=SessionListResponse)
async def get_my_sessions(
    include_stopped: bool = Query(False, description="Include stopped sessions"),
    limit: int = Query(50, ge=1, le=100, description="Number of sessions to return"),
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Get current user's lab sessions"""
    
    session_service = SessionService(db)
    
    if include_stopped:
        # Get all sessions (this would need a separate method)
        active_sessions = await session_service.get_user_active_sessions(current_user.id)
        sessions = active_sessions  # For now, just return active ones
    else:
        sessions = await session_service.get_user_active_sessions(current_user.id)
    
    # Convert to response format
    session_summaries = []
    for session in sessions[:limit]:
        # Get additional session details
        session_details = await session_service.get_session_with_details(session.id)
        
        if session_details:
            session_summary = SessionSummaryResponse(
                id=session.id,
                lab_id=session.lab_id,
                lab_name=session_details["lab"].name,
                status=session.status,
                access_method=session.access_method,
                network_range=session.network_range,
                started_at=session.started_at,
                expires_at=session.expires_at,
                time_remaining_minutes=session.time_remaining_minutes,
                vm_count=len(session_details["vm_instances"]),
                is_expired=session.is_expired
            )
            session_summaries.append(session_summary)
    
    return SessionListResponse(
        sessions=session_summaries,
        total=len(session_summaries),
        active_count=len([s for s in session_summaries if s.status == "active"])
    )


@router.get("/{session_id}", response_model=SessionDetailResponse)
async def get_session(
    session_id: uuid.UUID,
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Get specific session details"""
    
    session_service = SessionService(db)
    
    # Get session with all details
    session_details = await session_service.get_session_with_details(session_id)
    
    if not session_details:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    session = session_details["session"]
    
    # Check ownership
    if session.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: not your session"
        )
    
    # Build detailed response
    lab = session_details["lab"]
    vm_instances = session_details["vm_instances"]
    connection_info = session_details["connection_info"]
    
    return SessionDetailResponse(
        id=session.id,
        lab_id=session.lab_id,
        lab_name=lab.name,
        lab_description=lab.short_description,
        status=session.status,
        access_method=session.access_method,
        network_range=session.network_range,
        started_at=session.started_at,
        expires_at=session.expires_at,
        stopped_at=session.stopped_at,
        time_remaining_minutes=session.time_remaining_minutes,
        is_expired=session.is_expired,
        vm_instances=[
            {
                "id": vm.id,
                "name": vm.vm_name,
                "type": vm.vm_type,
                "status": vm.status,
                "ip_address": vm.ip_address,
                "connection_info": vm.connection_info
            } for vm in vm_instances
        ],
        connection_info=connection_info,
        session_logs=session.session_logs[-10:] if session.session_logs else [],  # Last 10 events
        allocated_resources=session.allocated_resources or {}
    )


@router.post("/v1/{session_id}/extend")
async def extend_session(
    session_id: uuid.UUID,
    extend_request: ExtendSessionRequest,
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Extend session duration"""
    
    session_service = SessionService(db)
    
    try:
        extended_session = await session_service.extend_session(
            session_id=session_id,
            additional_hours=extend_request.additional_hours,
            user_id=current_user.id
        )
        
        return {
            "success": True,
            "message": f"Session extended by {extend_request.additional_hours} hours",
            "session_id": session_id,
            "new_expires_at": extended_session.expires_at,
            "time_remaining_minutes": extended_session.time_remaining_minutes
        }
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to extend session"
        )


@router.post("/v1/{session_id}/stop")
async def stop_session(
    session_id: uuid.UUID,
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Stop a lab session"""
    
    session_service = SessionService(db)
    
    try:
        success = await session_service.stop_session(
            session_id=session_id,
            user_id=current_user.id
        )
        
        if success:
            return {
                "success": True,
                "message": "Session stopped successfully",
                "session_id": session_id
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to stop session"
            )
            
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to stop session"
        )


@router.get("/v1/{session_id}/access")
async def get_session_access(
    session_id: uuid.UUID,
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Get access information for session VMs"""
    
    session_service = SessionService(db)
    
    # Get session details
    session_details = await session_service.get_session_with_details(session_id)
    
    if not session_details:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    session = session_details["session"]
    
    # Check ownership
    if session.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: not your session"
        )
    
    # Check if session is active
    if session.status != "active":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Session is not active (current status: {session.status})"
        )
    
    # Check if session is expired
    if session.is_expired:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Session has expired"
        )
    
    return {
        "session_id": session_id,
        "access_method": session.access_method,
        "network_range": session.network_range,
        "connection_info": session_details["connection_info"],
        "vm_instances": [
            {
                "id": vm.id,
                "name": vm.vm_name,
                "type": vm.vm_type,
                "ip_address": vm.ip_address,
                "status": vm.status,
                "is_accessible": vm.is_accessible,
                "connection_info": vm.connection_info
            } for vm in session_details["vm_instances"]
        ],
        "guacamole_url": f"http://localhost:8080/guacamole" if session.access_method == "web" else None,
        "time_remaining_minutes": session.time_remaining_minutes
    }


@router.get("/v1/networks")
async def get_user_networks(
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Get user's network information"""
    
    network_service = NetworkService(db)
    
    # Get networks for this user
    user_networks = await network_service.list_user_networks(current_user.id)
    
    return {
        "user_id": current_user.id,
        "networks": user_networks,
        "total_networks": len(user_networks)
    }
