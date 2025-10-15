"""
VPN API endpoints for client certificate management and configuration
"""

import uuid
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.services.vpn_service import VPNService
from app.services.session_service import SessionService
from app.api.v1.endpoints.auth import get_current_user_dependency
from app.models.user import User
from app.schemas.vpn import (
    VPNStatusResponse,
    VPNConnectionRequest,
    VPNConnectionResponse,
    ClientConfigResponse
)
from loguru import logger

router = APIRouter(prefix="/vpn", tags=["VPN"])


@router.get("/status", response_model=VPNStatusResponse)
async def get_vpn_status(
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Get VPN server status and statistics"""
    
    vpn_service = VPNService(db)
    status = await vpn_service.get_vpn_status()
    
    return VPNStatusResponse(
        server_running=status.get('server_running', False),
        connected_clients=status.get('connected_clients', 0),
        active_certificates=status.get('active_certificates', 0),
        server_info=status.get('server_info', {})
    )


@router.post("/connect/{session_id}", response_model=VPNConnectionResponse)
async def connect_to_vpn(
    session_id: uuid.UUID,
    request: VPNConnectionRequest,
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Create VPN certificate and get connection details for a lab session"""
    
    # Verify session belongs to user
    session_service = SessionService(db)
    session = await session_service.get_session(session_id)
    
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    if session.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied to this session")
    
    if session.status != 'active':
        raise HTTPException(status_code=400, detail="Session must be active to connect VPN")
    
    # Create VPN certificate
    vpn_service = VPNService(db)
    success, message, certificate_id = await vpn_service.create_client_certificate(
        user_id=current_user.id,
        session_id=session_id,
        certificate_name=request.certificate_name
    )
    
    if not success:
        logger.error(f"Failed to create VPN certificate for user {current_user.id}: {message}")
        raise HTTPException(status_code=500, detail=f"Failed to create VPN certificate: {message}")
    
    # Add routes for user's lab network
    if session.network_range:
        route_success, route_message = await vpn_service.add_user_routes(
            user_id=current_user.id,
            lab_network=session.network_range
        )
        if not route_success:
            logger.warning(f"Failed to add routes for user {current_user.id}: {route_message}")
    
    return VPNConnectionResponse(
        certificate_id=uuid.UUID(certificate_id),
        session_id=session_id,
        status="ready",
        message="VPN certificate created successfully",
        server_endpoint="localhost:1194",  # This should come from config
        lab_network=session.network_range
    )


@router.delete("/disconnect/{session_id}")
async def disconnect_from_vpn(
    session_id: uuid.UUID,
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Revoke VPN certificate for a session"""
    
    # Find active certificate for this session
    vpn_service = VPNService(db)
    
    # Get certificate by session and user
    from sqlalchemy import select, and_
    from app.models.vpn import VPNCertificate
    
    query = select(VPNCertificate).where(
        and_(
            VPNCertificate.session_id == session_id,
            VPNCertificate.user_id == current_user.id,
            VPNCertificate.status == 'active'
        )
    )
    
    result = await db.execute(query)
    certificate = result.scalar_one_or_none()
    
    if not certificate:
        raise HTTPException(status_code=404, detail="No active VPN certificate found for this session")
    
    # Revoke certificate
    success, message = await vpn_service.revoke_client_certificate(certificate.id)
    
    if not success:
        logger.error(f"Failed to revoke VPN certificate {certificate.id}: {message}")
        raise HTTPException(status_code=500, detail=f"Failed to revoke certificate: {message}")
    
    return {"message": "VPN certificate revoked successfully"}


@router.get("/config/{session_id}", response_class=PlainTextResponse)
async def get_vpn_config(
    session_id: uuid.UUID,
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Download OpenVPN client configuration file"""
    
    # Find active certificate for this session
    from sqlalchemy import select, and_
    from app.models.vpn import VPNCertificate
    
    query = select(VPNCertificate).where(
        and_(
            VPNCertificate.session_id == session_id,
            VPNCertificate.user_id == current_user.id,
            VPNCertificate.status == 'active'
        )
    )
    
    result = await db.execute(query)
    certificate = result.scalar_one_or_none()
    
    if not certificate:
        raise HTTPException(status_code=404, detail="No active VPN certificate found for this session")
    
    # Get client configuration
    vpn_service = VPNService(db)
    config = await vpn_service.get_client_config(certificate.id)
    
    if not config:
        raise HTTPException(status_code=500, detail="Failed to generate client configuration")
    
    return PlainTextResponse(
        content=config,
        headers={
            "Content-Disposition": f"attachment; filename=cyberlab_session_{session_id}.ovpn"
        }
    )


@router.get("/download/{certificate_id}", response_class=PlainTextResponse)
async def download_vpn_config(
    certificate_id: uuid.UUID,
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Download OpenVPN client configuration by certificate ID"""
    
    # Verify certificate belongs to user
    from sqlalchemy import select, and_
    from app.models.vpn import VPNCertificate
    
    query = select(VPNCertificate).where(
        and_(
            VPNCertificate.id == certificate_id,
            VPNCertificate.user_id == current_user.id,
            VPNCertificate.status == 'active'
        )
    )
    
    result = await db.execute(query)
    certificate = result.scalar_one_or_none()
    
    if not certificate:
        raise HTTPException(status_code=404, detail="Certificate not found or access denied")
    
    # Get client configuration
    vpn_service = VPNService(db)
    config = await vpn_service.get_client_config(certificate_id)
    
    if not config:
        raise HTTPException(status_code=500, detail="Failed to generate client configuration")
    
    return PlainTextResponse(
        content=config,
        headers={
            "Content-Disposition": f"attachment; filename={certificate.common_name}.ovpn"
        }
    )


@router.get("/certificates")
async def list_user_certificates(
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """List all VPN certificates for the current user"""
    
    from sqlalchemy import select
    from app.models.vpn import VPNCertificate
    
    query = select(VPNCertificate).where(
        VPNCertificate.user_id == current_user.id
    ).order_by(VPNCertificate.issued_at.desc())
    
    result = await db.execute(query)
    certificates = result.scalars().all()
    
    certificate_list = []
    for cert in certificates:
        certificate_list.append({
            "id": str(cert.id),
            "common_name": cert.common_name,
            "session_id": str(cert.session_id) if cert.session_id else None,
            "issued_at": cert.issued_at.isoformat(),
            "expires_at": cert.expires_at.isoformat() if cert.expires_at else None,
            "status": cert.status,
            "is_active": cert.is_active,
            "is_expired": cert.is_expired
        })
    
    return {"certificates": certificate_list}


# Admin endpoints (require admin privileges)
@router.post("/server/start")
async def start_vpn_server(
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Start the VPN server (admin only)"""
    
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin privileges required")
    
    vpn_service = VPNService(db)
    success, message = await vpn_service.start_vpn_server()
    
    if not success:
        raise HTTPException(status_code=500, detail=message)
    
    return {"message": message}


@router.post("/server/stop")
async def stop_vpn_server(
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Stop the VPN server (admin only)"""
    
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin privileges required")
    
    vpn_service = VPNService(db)
    success, message = await vpn_service.stop_vpn_server()
    
    if not success:
        raise HTTPException(status_code=500, detail=message)
    
    return {"message": message}


@router.post("/cleanup")
async def cleanup_expired_certificates(
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Clean up expired certificates (admin only)"""
    
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin privileges required")
    
    vpn_service = VPNService(db)
    cleaned_count = await vpn_service.cleanup_expired_certificates()
    
    return {"message": f"Cleaned up {cleaned_count} expired certificates"}