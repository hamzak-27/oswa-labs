"""
Lab session models for tracking active user lab instances
"""

from sqlalchemy import Column, String, DateTime, ForeignKey, Integer, Boolean
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from enum import Enum
from datetime import datetime, timedelta
import uuid

from app.core.database import Base


class SessionStatus(str, Enum):
    """Lab session status"""
    PROVISIONING = "provisioning"
    ACTIVE = "active"
    PAUSED = "paused"
    STOPPING = "stopping"
    STOPPED = "stopped"
    EXPIRED = "expired"
    ERROR = "error"


class AccessMethod(str, Enum):
    """Lab access method"""
    VPN = "vpn"
    WEB = "web"


class VMStatus(str, Enum):
    """Virtual machine status"""
    CREATING = "creating"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"
    DELETED = "deleted"


class LabSession(Base):
    """Lab session tracking user's active lab instances"""
    
    __tablename__ = "lab_sessions"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Relationships
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    lab_id = Column(UUID(as_uuid=True), ForeignKey("labs.id"), nullable=False)
    
    # Session metadata
    status = Column(String(20), default=SessionStatus.PROVISIONING)
    access_method = Column(String(10), nullable=False)  # VPN or WEB
    
    # Network configuration
    network_range = Column(String(20))  # e.g., "10.10.123.0/24"
    vpn_config_id = Column(String(100))  # Reference to VPN configuration
    
    # Guacamole integration (for web access)
    guacamole_connections = Column(JSONB)  # Guacamole connection IDs
    """
    Example guacamole_connections:
    {
        "kali_box": "connection_id_123",
        "windows_box": "connection_id_456"
    }
    """
    
    # Session timing
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
    last_activity = Column(DateTime(timezone=True), server_default=func.now())
    stopped_at = Column(DateTime(timezone=True))
    
    # Resource allocation
    allocated_resources = Column(JSONB)
    """
    Example allocated_resources:
    {
        "total_cpu_cores": 4,
        "total_ram_mb": 8192,
        "storage_gb": 50,
        "network_bandwidth_mbps": 100
    }
    """
    
    # Session metadata
    client_info = Column(JSONB)  # User's browser/client information
    session_logs = Column(JSONB)  # Important session events
    
    # Relationships
    vm_instances = relationship("VMInstance", back_populates="session", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<LabSession(id={self.id}, user_id={self.user_id}, status='{self.status}')>"
    
    @property
    def is_active(self) -> bool:
        """Check if session is currently active"""
        return self.status == SessionStatus.ACTIVE
    
    @property
    def is_expired(self) -> bool:
        """Check if session has expired"""
        return datetime.utcnow() > self.expires_at
    
    @property
    def time_remaining_minutes(self) -> int:
        """Get remaining time in minutes"""
        if self.is_expired:
            return 0
        remaining = self.expires_at - datetime.utcnow()
        return max(0, int(remaining.total_seconds() / 60))
    
    def extend_session(self, hours: int = 2):
        """Extend session by specified hours"""
        self.expires_at = self.expires_at + timedelta(hours=hours)
    
    def update_last_activity(self):
        """Update last activity timestamp"""
        self.last_activity = datetime.utcnow()


class VMInstance(Base):
    """Individual VM instance within a lab session"""
    
    __tablename__ = "vm_instances"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Relationships
    session_id = Column(UUID(as_uuid=True), ForeignKey("lab_sessions.id"), nullable=False)
    session = relationship("LabSession", back_populates="vm_instances")
    
    # VM identification
    vm_name = Column(String(100), nullable=False)  # e.g., "kali-box", "web-server"
    vm_type = Column(String(50), nullable=False)   # e.g., "attack_box", "target"
    template_id = Column(String(100), nullable=False)  # Source template
    
    # Proxmox/Hypervisor details
    proxmox_vm_id = Column(Integer)  # Proxmox VM ID
    proxmox_node = Column(String(50))  # Proxmox node name
    
    # VM status and configuration
    status = Column(String(20), default=VMStatus.CREATING)
    ip_address = Column(String(15))  # IPv4 address
    mac_address = Column(String(17))  # MAC address
    
    # VM specifications
    cpu_cores = Column(Integer, default=2)
    ram_mb = Column(Integer, default=2048)
    disk_gb = Column(Integer, default=20)
    
    # Access credentials (encrypted)
    ssh_username = Column(String(50))
    ssh_password = Column(String(255))  # Encrypted
    rdp_username = Column(String(50))
    rdp_password = Column(String(255))  # Encrypted
    
    # Guacamole connection details
    guacamole_connection_id = Column(String(100))
    guacamole_protocol = Column(String(10))  # ssh, rdp, vnc
    
    # VM lifecycle
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    started_at = Column(DateTime(timezone=True))
    stopped_at = Column(DateTime(timezone=True))
    
    # Container-specific fields
    container_id = Column(String(100))  # Docker container ID
    container_name = Column(String(100))  # Docker container name
    container_image = Column(String(200))  # Docker image used
    
    # VM state and snapshots
    current_snapshot = Column(String(100))  # Current snapshot name
    custom_config = Column(JSONB)  # Custom VM configuration
    
    def __repr__(self):
        return f"<VMInstance(id={self.id}, name='{self.vm_name}', status='{self.status}')>"
    
    @property
    def is_running(self) -> bool:
        """Check if VM is currently running"""
        return self.status == VMStatus.RUNNING
    
    @property
    def is_accessible(self) -> bool:
        """Check if VM is accessible to users"""
        return self.status in [VMStatus.RUNNING]
    
    @property
    def connection_info(self) -> dict:
        """Get connection information for this VM"""
        info = {
            "ip": self.ip_address,
            "status": self.status,
            "type": self.vm_type
        }
        
        if self.guacamole_connection_id:
            info["guacamole_connection"] = self.guacamole_connection_id
            info["protocol"] = self.guacamole_protocol
        
        if self.ssh_username:
            info["ssh"] = {
                "username": self.ssh_username,
                "port": 22
            }
        
        if self.rdp_username:
            info["rdp"] = {
                "username": self.rdp_username,
                "port": 3389
            }
        
        return info
