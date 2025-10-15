"""
VPN Certificate and Connection Log database models
"""

import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Text, ForeignKey, Integer, BigInteger
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.orm import relationship

from app.core.database import Base


class VPNCertificate(Base):
    """Model for VPN client certificates"""
    
    __tablename__ = "vpn_certificates"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    session_id = Column(UUID(as_uuid=True), ForeignKey("lab_sessions.id"), nullable=True)
    common_name = Column(String(255), nullable=False, unique=True)
    certificate_pem = Column(Text, nullable=False)
    private_key_pem = Column(Text, nullable=False)
    serial_number = Column(BigInteger, nullable=False, unique=True)
    status = Column(String(20), nullable=False, default='active')  # active, revoked, expired
    issued_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    revocation_reason = Column(String(100), nullable=True)
    client_config = Column(Text, nullable=True)  # Cached OpenVPN client configuration
    last_connected_at = Column(DateTime, nullable=True)
    connection_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="vpn_certificates")
    session = relationship("LabSession", back_populates="vpn_certificate")
    connection_logs = relationship("VPNConnectionLog", back_populates="certificate", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<VPNCertificate(id={self.id}, common_name={self.common_name}, status={self.status})>"
    
    @property
    def is_active(self) -> bool:
        """Check if certificate is currently active"""
        if self.status != 'active':
            return False
        
        if self.expires_at and self.expires_at < datetime.utcnow():
            return False
            
        return True
    
    @property
    def is_expired(self) -> bool:
        """Check if certificate has expired"""
        if self.expires_at and self.expires_at < datetime.utcnow():
            return True
        return False


class VPNConnectionLog(Base):
    """Model for VPN connection logs and statistics"""
    
    __tablename__ = "vpn_connection_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    certificate_id = Column(UUID(as_uuid=True), ForeignKey("vpn_certificates.id"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    session_id = Column(UUID(as_uuid=True), ForeignKey("lab_sessions.id"), nullable=True)
    client_ip = Column(INET, nullable=False)  # Client's real IP address
    vpn_ip = Column(INET, nullable=False)     # Assigned VPN IP address
    connected_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    disconnected_at = Column(DateTime, nullable=True)
    bytes_received = Column(BigInteger, nullable=False, default=0)
    bytes_sent = Column(BigInteger, nullable=False, default=0)
    disconnect_reason = Column(String(100), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    
    # Relationships
    certificate = relationship("VPNCertificate", back_populates="connection_logs")
    user = relationship("User")
    session = relationship("LabSession")
    
    def __repr__(self):
        return f"<VPNConnectionLog(id={self.id}, client_ip={self.client_ip}, vpn_ip={self.vpn_ip})>"
    
    @property
    def duration_seconds(self) -> int:
        """Calculate connection duration in seconds"""
        if not self.disconnected_at:
            # Still connected
            return int((datetime.utcnow() - self.connected_at).total_seconds())
        return int((self.disconnected_at - self.connected_at).total_seconds())
    
    @property
    def is_active(self) -> bool:
        """Check if this connection is still active"""
        return self.disconnected_at is None
