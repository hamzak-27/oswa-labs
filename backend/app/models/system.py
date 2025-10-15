"""
System models for audit logging and metrics
"""

from sqlalchemy import Column, String, DateTime, ForeignKey, Integer, Text, Float
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.sql import func
from enum import Enum
from datetime import datetime
import uuid

from app.core.database import Base


class AuditEventType(str, Enum):
    """Types of audit events"""
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    LAB_START = "lab_start"
    LAB_STOP = "lab_stop"
    LAB_RESET = "lab_reset"
    FLAG_SUBMIT = "flag_submit"
    VM_CREATE = "vm_create"
    VM_DELETE = "vm_delete"
    VPN_DOWNLOAD = "vpn_download"
    ADMIN_ACTION = "admin_action"
    SECURITY_EVENT = "security_event"
    ERROR = "error"


class LogLevel(str, Enum):
    """Log levels"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AuditLog(Base):
    """Audit log for tracking system events and user actions"""
    
    __tablename__ = "audit_logs"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Event details
    event_type = Column(String(50), nullable=False, index=True)
    log_level = Column(String(20), default=LogLevel.INFO)
    message = Column(Text, nullable=False)
    
    # User context (optional)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    username = Column(String(50))  # Denormalized for performance
    
    # Resource context
    lab_id = Column(UUID(as_uuid=True))
    session_id = Column(UUID(as_uuid=True))
    vm_id = Column(UUID(as_uuid=True))
    
    # Request context
    ip_address = Column(String(15))
    user_agent = Column(String(500))
    request_id = Column(String(100))  # For tracing requests
    
    # Event data
    event_data = Column(JSONB)  # Additional structured data
    """
    Example event_data for different events:
    
    USER_LOGIN: {
        "login_method": "password",
        "success": true,
        "failed_attempts": 0
    }
    
    LAB_START: {
        "lab_name": "Buffer Overflow Lab",
        "access_method": "web",
        "vm_count": 3,
        "network_range": "10.10.123.0/24"
    }
    
    FLAG_SUBMIT: {
        "flag_type": "user",
        "correct": true,
        "points_awarded": 10,
        "attempt_number": 2
    }
    """
    
    # Performance metrics
    response_time_ms = Column(Integer)  # API response time
    
    # Timestamps
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    
    def __repr__(self):
        return f"<AuditLog(id={self.id}, event_type='{self.event_type}', timestamp={self.timestamp})>"


class SystemMetrics(Base):
    """System performance and usage metrics"""
    
    __tablename__ = "system_metrics"
    
    # Primary key  
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Metric identification
    metric_name = Column(String(100), nullable=False, index=True)
    metric_type = Column(String(50), nullable=False)  # counter, gauge, histogram
    
    # Metric value
    value = Column(Float, nullable=False)
    unit = Column(String(20))  # bytes, seconds, count, percentage
    
    # Context tags
    tags = Column(JSONB)  # Key-value tags for filtering/grouping
    """
    Example tags:
    {
        "service": "api_server",
        "endpoint": "/api/v1/labs",
        "user_id": "123e4567-e89b-12d3-a456-426614174000",
        "lab_id": "456e7890-e89b-12d3-a456-426614174001"
    }
    """
    
    # Aggregation support
    aggregation_window = Column(String(20))  # 1m, 5m, 1h, 1d
    
    # Timestamps
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    
    def __repr__(self):
        return f"<SystemMetrics(metric_name='{self.metric_name}', value={self.value}, timestamp={self.timestamp})>"


# Common system metrics we'll track:
SYSTEM_METRICS = {
    # API Performance
    "api_request_duration": "Response time for API requests",
    "api_request_count": "Total API requests",
    "api_error_rate": "API error rate percentage",
    
    # Lab Usage
    "active_lab_sessions": "Number of active lab sessions",
    "lab_start_count": "Labs started counter",
    "lab_completion_rate": "Lab completion rate percentage",
    
    # VM Management
    "vm_provisioning_time": "Time to provision new VMs",
    "vm_count_total": "Total VMs running",
    "vm_cpu_usage": "VM CPU utilization percentage",
    "vm_memory_usage": "VM memory utilization percentage",
    
    # User Activity
    "active_users": "Number of active users",
    "user_registration_count": "New user registrations",
    "average_session_duration": "Average lab session duration",
    
    # System Resources
    "host_cpu_usage": "Host system CPU usage",
    "host_memory_usage": "Host system memory usage", 
    "host_disk_usage": "Host system disk usage",
    "network_bandwidth_usage": "Network bandwidth utilization"
}
