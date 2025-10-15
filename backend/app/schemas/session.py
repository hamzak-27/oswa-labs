"""
Session schemas for API request/response validation
"""

from pydantic import BaseModel, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid


class SessionSummaryResponse(BaseModel):
    """Session summary for listing"""
    id: uuid.UUID
    lab_id: uuid.UUID
    lab_name: str
    status: str
    access_method: str
    network_range: str
    started_at: datetime
    expires_at: datetime
    time_remaining_minutes: int
    vm_count: int
    is_expired: bool
    
    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "lab_id": "456e7890-e89b-12d3-a456-426614174001",
                "lab_name": "SQL Injection Playground",
                "status": "active",
                "access_method": "web",
                "network_range": "10.10.123.0/24",
                "started_at": "2023-12-01T10:00:00Z",
                "expires_at": "2023-12-01T14:00:00Z",
                "time_remaining_minutes": 180,
                "vm_count": 2,
                "is_expired": False
            }
        }


class SessionListResponse(BaseModel):
    """Paginated session list response"""
    sessions: List[SessionSummaryResponse]
    total: int
    active_count: int
    
    class Config:
        json_schema_extra = {
            "example": {
                "sessions": [
                    {
                        "lab_name": "SQL Injection Playground",
                        "status": "active",
                        "time_remaining_minutes": 180
                    }
                ],
                "total": 3,
                "active_count": 2
            }
        }


class VMInstanceResponse(BaseModel):
    """VM instance information"""
    id: uuid.UUID
    name: str
    type: str
    status: str
    ip_address: Optional[str]
    connection_info: Dict[str, Any]


class SessionDetailResponse(BaseModel):
    """Detailed session information"""
    id: uuid.UUID
    lab_id: uuid.UUID
    lab_name: str
    lab_description: Optional[str]
    status: str
    access_method: str
    network_range: str
    started_at: datetime
    expires_at: datetime
    stopped_at: Optional[datetime]
    time_remaining_minutes: int
    is_expired: bool
    vm_instances: List[Dict[str, Any]]
    connection_info: List[Dict[str, Any]]
    session_logs: List[Dict[str, Any]]
    allocated_resources: Dict[str, Any]
    
    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "lab_id": "456e7890-e89b-12d3-a456-426614174001",
                "lab_name": "SQL Injection Playground",
                "lab_description": "Practice SQL injection techniques",
                "status": "active",
                "access_method": "web",
                "network_range": "10.10.123.0/24",
                "started_at": "2023-12-01T10:00:00Z",
                "expires_at": "2023-12-01T14:00:00Z",
                "time_remaining_minutes": 180,
                "is_expired": False,
                "vm_instances": [
                    {
                        "id": "vm-123",
                        "name": "kali-box",
                        "type": "attack_box",
                        "status": "running",
                        "ip_address": "10.10.123.10"
                    }
                ],
                "connection_info": [],
                "session_logs": [],
                "allocated_resources": {
                    "total_cpu_cores": 4,
                    "total_ram_mb": 8192
                }
            }
        }


class ExtendSessionRequest(BaseModel):
    """Request to extend session duration"""
    additional_hours: int
    
    @validator("additional_hours")
    def validate_additional_hours(cls, v):
        if v < 1:
            raise ValueError("Additional hours must be at least 1")
        if v > 8:
            raise ValueError("Cannot extend session by more than 8 hours at once")
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "additional_hours": 2
            }
        }


class StartSessionRequest(BaseModel):
    """Request to start a lab session"""
    access_method: str
    attack_box_os: Optional[str] = "kali"
    session_duration_hours: Optional[int] = None
    
    @validator("access_method")
    def validate_access_method(cls, v):
        if v not in ["vpn", "web"]:
            raise ValueError("Access method must be 'vpn' or 'web'")
        return v
    
    @validator("attack_box_os")
    def validate_attack_box_os(cls, v):
        if v and v not in ["kali", "windows"]:
            raise ValueError("Attack box OS must be 'kali' or 'windows'")
        return v
    
    @validator("session_duration_hours")
    def validate_session_duration(cls, v):
        if v is not None:
            if v < 1:
                raise ValueError("Session duration must be at least 1 hour")
            if v > 12:
                raise ValueError("Session duration cannot exceed 12 hours")
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "access_method": "web",
                "attack_box_os": "kali",
                "session_duration_hours": 4
            }
        }


class SessionActionResponse(BaseModel):
    """Response for session actions (start, stop, extend)"""
    success: bool
    message: str
    session_id: uuid.UUID
    data: Optional[Dict[str, Any]] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "success": True,
                "message": "Session started successfully",
                "session_id": "123e4567-e89b-12d3-a456-426614174000",
                "data": {
                    "expires_at": "2023-12-01T14:00:00Z",
                    "network_range": "10.10.123.0/24"
                }
            }
        }


class NetworkInfoResponse(BaseModel):
    """Network information response"""
    user_id: uuid.UUID
    networks: List[Dict[str, Any]]
    total_networks: int
    
    class Config:
        json_schema_extra = {
            "example": {
                "user_id": "123e4567-e89b-12d3-a456-426614174000",
                "networks": [
                    {
                        "id": "network-123",
                        "name": "cyberlab_user_123e4567e89b",
                        "subnet": "10.10.123.0/24",
                        "container_count": 2,
                        "created_at": "2023-12-01T10:00:00Z"
                    }
                ],
                "total_networks": 1
            }
        }
