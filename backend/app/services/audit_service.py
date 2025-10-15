"""
Audit service for logging system events and user actions
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional, Dict, Any, List
from datetime import datetime
import uuid

from app.models.system import AuditLog, AuditEventType, LogLevel
from loguru import logger


class AuditService:
    """Service for audit logging and security events"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def log_event(
        self,
        event_type: AuditEventType,
        message: str,
        user_id: Optional[uuid.UUID] = None,
        username: Optional[str] = None,
        lab_id: Optional[uuid.UUID] = None,
        session_id: Optional[uuid.UUID] = None,
        vm_id: Optional[uuid.UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_id: Optional[str] = None,
        log_level: LogLevel = LogLevel.INFO,
        event_data: Optional[Dict[str, Any]] = None,
        response_time_ms: Optional[int] = None
    ) -> AuditLog:
        """Log an audit event"""
        
        audit_log = AuditLog(
            id=uuid.uuid4(),
            event_type=event_type,
            log_level=log_level,
            message=message,
            user_id=user_id,
            username=username,
            lab_id=lab_id,
            session_id=session_id,
            vm_id=vm_id,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            event_data=event_data or {},
            response_time_ms=response_time_ms
        )
        
        self.db.add(audit_log)
        await self.db.commit()
        
        # Also log to application logger
        log_message = f"[{event_type}] {message}"
        if user_id:
            log_message += f" | User: {username or user_id}"
        if ip_address:
            log_message += f" | IP: {ip_address}"
        
        if log_level == LogLevel.ERROR:
            logger.error(log_message)
        elif log_level == LogLevel.WARNING:
            logger.warning(log_message)
        elif log_level == LogLevel.CRITICAL:
            logger.critical(log_message)
        else:
            logger.info(log_message)
        
        return audit_log
    
    async def get_user_audit_logs(
        self,
        user_id: uuid.UUID,
        event_types: Optional[List[AuditEventType]] = None,
        skip: int = 0,
        limit: int = 100
    ) -> List[AuditLog]:
        """Get audit logs for a specific user"""
        
        query = select(AuditLog).where(AuditLog.user_id == user_id)
        
        if event_types:
            query = query.where(AuditLog.event_type.in_(event_types))
        
        query = query.offset(skip).limit(limit).order_by(AuditLog.timestamp.desc())
        
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def get_recent_events(
        self,
        hours: int = 24,
        event_types: Optional[List[AuditEventType]] = None,
        skip: int = 0,
        limit: int = 100
    ) -> List[AuditLog]:
        """Get recent audit events"""
        
        since = datetime.utcnow() - timedelta(hours=hours)
        
        query = select(AuditLog).where(AuditLog.timestamp >= since)
        
        if event_types:
            query = query.where(AuditLog.event_type.in_(event_types))
        
        query = query.offset(skip).limit(limit).order_by(AuditLog.timestamp.desc())
        
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def get_security_events(
        self,
        hours: int = 24,
        skip: int = 0,
        limit: int = 50
    ) -> List[AuditLog]:
        """Get recent security-related events"""
        
        security_events = [
            AuditEventType.USER_LOGIN,
            AuditEventType.SECURITY_EVENT,
            AuditEventType.ERROR
        ]
        
        return await self.get_recent_events(
            hours=hours,
            event_types=security_events,
            skip=skip,
            limit=limit
        )
    
    async def count_failed_login_attempts(
        self,
        username: str,
        ip_address: str,
        hours: int = 1
    ) -> int:
        """Count failed login attempts for rate limiting"""
        
        since = datetime.utcnow() - timedelta(hours=hours)
        
        query = select(AuditLog).where(
            AuditLog.event_type == AuditEventType.USER_LOGIN,
            AuditLog.timestamp >= since,
            AuditLog.username == username,
            AuditLog.ip_address == ip_address,
            AuditLog.event_data.contains({"success": False})
        )
        
        result = await self.db.execute(query)
        return len(result.scalars().all())
    
    async def log_security_event(
        self,
        message: str,
        severity: LogLevel = LogLevel.WARNING,
        user_id: Optional[uuid.UUID] = None,
        ip_address: Optional[str] = None,
        additional_data: Optional[Dict[str, Any]] = None
    ) -> AuditLog:
        """Log a security-related event"""
        
        return await self.log_event(
            event_type=AuditEventType.SECURITY_EVENT,
            message=message,
            log_level=severity,
            user_id=user_id,
            ip_address=ip_address,
            event_data=additional_data
        )
    
    async def log_admin_action(
        self,
        action: str,
        admin_user_id: uuid.UUID,
        target_user_id: Optional[uuid.UUID] = None,
        additional_data: Optional[Dict[str, Any]] = None
    ) -> AuditLog:
        """Log administrative actions"""
        
        message = f"Admin action: {action}"
        if target_user_id:
            message += f" | Target user: {target_user_id}"
        
        return await self.log_event(
            event_type=AuditEventType.ADMIN_ACTION,
            message=message,
            user_id=admin_user_id,
            event_data=additional_data or {}
        )
