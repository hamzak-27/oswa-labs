"""
VPN-related Pydantic schemas
"""

import uuid
from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class VPNConnectionRequest(BaseModel):
    """Request model for VPN connection"""
    certificate_name: Optional[str] = Field(
        None, 
        description="Custom certificate name (optional, auto-generated if not provided)"
    )


class VPNConnectionResponse(BaseModel):
    """Response model for VPN connection"""
    certificate_id: uuid.UUID = Field(description="Generated certificate ID")
    session_id: uuid.UUID = Field(description="Lab session ID")
    status: str = Field(description="Connection status")
    message: str = Field(description="Status message")
    server_endpoint: str = Field(description="VPN server endpoint (host:port)")
    lab_network: Optional[str] = Field(description="Lab network CIDR")


class VPNStatusResponse(BaseModel):
    """Response model for VPN server status"""
    server_running: bool = Field(description="Whether VPN server is running")
    connected_clients: int = Field(description="Number of connected VPN clients")
    active_certificates: int = Field(description="Number of active certificates")
    server_info: Dict[str, Any] = Field(default_factory=dict, description="Server details")


class ClientConfigResponse(BaseModel):
    """Response model for client configuration"""
    certificate_id: uuid.UUID = Field(description="Certificate ID")
    config_content: str = Field(description="OpenVPN client configuration")
    filename: str = Field(description="Suggested filename for the config")


class VPNCertificateResponse(BaseModel):
    """Response model for VPN certificate details"""
    id: uuid.UUID = Field(description="Certificate ID")
    certificate_name: str = Field(description="Certificate name")
    session_id: Optional[uuid.UUID] = Field(description="Associated session ID")
    issued_at: datetime = Field(description="Certificate issue date")
    expires_at: Optional[datetime] = Field(description="Certificate expiry date")
    revoked_at: Optional[datetime] = Field(description="Certificate revocation date")
    status: str = Field(description="Certificate status (active, revoked, expired)")
    is_active: bool = Field(description="Whether certificate is currently active")
    is_expired: bool = Field(description="Whether certificate has expired")


class VPNCertificateListResponse(BaseModel):
    """Response model for listing VPN certificates"""
    certificates: list[VPNCertificateResponse] = Field(description="List of user certificates")


class VPNServerControlResponse(BaseModel):
    """Response model for VPN server control operations"""
    message: str = Field(description="Operation result message")


class VPNCleanupResponse(BaseModel):
    """Response model for certificate cleanup operations"""
    message: str = Field(description="Cleanup result message")
    cleaned_count: int = Field(description="Number of certificates cleaned up")