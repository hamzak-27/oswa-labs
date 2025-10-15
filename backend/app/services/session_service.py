"""
Session service for lab session management
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func, update
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timedelta
import uuid
import asyncio

from app.models.session import LabSession, VMInstance, SessionStatus, AccessMethod, VMStatus
from app.models.user import User
from app.models.lab import Lab
from app.models.progress import UserProgress, CompletionStatus
from app.core.config import settings
from app.core.redis import redis_client
from loguru import logger


class SessionService:
    """Service class for lab session operations"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def create_session(
        self,
        user: User,
        lab: Lab,
        access_method: AccessMethod,
        attack_box_os: str = "kali",
        session_duration_hours: int = None
    ) -> LabSession:
        """Create a new lab session for a user"""
        
        # Check if user can start a new session
        can_start, reason = await self._can_user_start_session(user)
        if not can_start:
            raise ValueError(f"Cannot start session: {reason}")
        
        # Set session duration
        if session_duration_hours is None:
            session_duration_hours = settings.DEFAULT_SESSION_DURATION_HOURS
        
        # Generate unique network range for this user
        network_range = await self._allocate_user_network(user.id)
        
        # Create session record
        expires_at = datetime.utcnow() + timedelta(hours=session_duration_hours)
        
        session = LabSession(
            id=uuid.uuid4(),
            user_id=user.id,
            lab_id=lab.id,
            status=SessionStatus.PROVISIONING,
            access_method=access_method.value,
            network_range=network_range,
            expires_at=expires_at,
            allocated_resources={
                "total_cpu_cores": 0,
                "total_ram_mb": 0,
                "storage_gb": 0,
                "network_bandwidth_mbps": 100
            },
            client_info={
                "attack_box_os": attack_box_os,
                "created_via": "api"
            },
            session_logs=[]
        )
        
        self.db.add(session)
        await self.db.commit()
        await self.db.refresh(session)
        
        # Log session creation
        await self._log_session_event(session, "session_created", {
            "lab_name": lab.name,
            "access_method": access_method.value,
            "network_range": network_range,
            "duration_hours": session_duration_hours
        })
        
        # Initialize user progress if not exists
        await self._initialize_user_progress(user.id, lab.id)
        
        # Cache session data
        await self._cache_session(session)
        
        logger.info(f"Created session {session.id} for user {user.id} on lab {lab.id}")
        return session
    
    async def start_session(self, session_id: uuid.UUID) -> LabSession:
        """Start the lab session (provision VMs and networks)"""
        
        session = await self.get_session_by_id(session_id)
        if not session:
            raise ValueError("Session not found")
        
        if session.status != SessionStatus.PROVISIONING:
            raise ValueError(f"Cannot start session in status: {session.status}")
        
        try:
            # Import VM Service here to avoid circular imports
            from app.services.vm_service import VMService
            vm_service = VMService(self.db)
            
            # Provision lab environment
            success, message = await vm_service.provision_lab_environment(session_id)
            
            if not success:
                raise Exception(f"VM provisioning failed: {message}")
            
            # Update session status to active
            session.status = SessionStatus.ACTIVE
            await self.db.commit()
            
            # Log session start
            await self._log_session_event(session, "session_started", {
                "provision_message": message,
                "status": "active"
            })
            
            logger.info(f"Started session {session.id}: {message}")
            return session
            
        except Exception as e:
            # Mark session as error state
            session.status = SessionStatus.ERROR
            await self.db.commit()
            
            await self._log_session_event(session, "session_start_failed", {
                "error": str(e)
            })
            
            logger.error(f"Failed to start session {session.id}: {e}")
            raise
    
    async def stop_session(self, session_id: uuid.UUID, user_id: uuid.UUID = None) -> bool:
        """Stop a lab session and cleanup resources"""
        
        session = await self.get_session_by_id(session_id)
        if not session:
            return False
        
        # Check ownership if user_id provided
        if user_id and session.user_id != user_id:
            raise ValueError("Access denied: not your session")
        
        if session.status in [SessionStatus.STOPPED, SessionStatus.STOPPING]:
            return True  # Already stopped/stopping
        
        try:
            # Update session status
            old_status = session.status
            session.status = SessionStatus.STOPPING
            session.stopped_at = datetime.utcnow()
            await self.db.commit()
            
            # Stop all VM instances (will be implemented in VM service)
            await self._stop_session_vms(session.id)
            
            # Cleanup network resources
            await self._cleanup_session_network(session)
            
            # Final status update
            session.status = SessionStatus.STOPPED
            await self.db.commit()
            
            # Update user progress with session time
            if old_status == SessionStatus.ACTIVE:
                await self._update_session_time_spent(session)
            
            # Remove from cache
            await self._remove_session_from_cache(session.id)
            
            await self._log_session_event(session, "session_stopped", {
                "previous_status": old_status,
                "duration_minutes": self._calculate_session_duration_minutes(session)
            })
            
            logger.info(f"Stopped session {session.id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to stop session {session.id}: {e}")
            session.status = SessionStatus.ERROR
            await self.db.commit()
            return False
    
    async def extend_session(
        self,
        session_id: uuid.UUID,
        additional_hours: int,
        user_id: uuid.UUID = None
    ) -> LabSession:
        """Extend session duration"""
        
        session = await self.get_session_by_id(session_id)
        if not session:
            raise ValueError("Session not found")
        
        # Check ownership
        if user_id and session.user_id != user_id:
            raise ValueError("Access denied: not your session")
        
        if session.status != SessionStatus.ACTIVE:
            raise ValueError(f"Cannot extend session in status: {session.status}")
        
        # Extend expiration time
        old_expires_at = session.expires_at
        session.expires_at = session.expires_at + timedelta(hours=additional_hours)
        await self.db.commit()
        
        await self._log_session_event(session, "session_extended", {
            "additional_hours": additional_hours,
            "old_expires_at": old_expires_at.isoformat(),
            "new_expires_at": session.expires_at.isoformat()
        })
        
        logger.info(f"Extended session {session.id} by {additional_hours} hours")
        return session
    
    async def get_user_active_sessions(self, user_id: uuid.UUID) -> List[LabSession]:
        """Get all active sessions for a user"""
        
        query = select(LabSession).where(
            and_(
                LabSession.user_id == user_id,
                LabSession.status.in_([
                    SessionStatus.PROVISIONING,
                    SessionStatus.ACTIVE,
                    SessionStatus.PAUSED
                ])
            )
        ).order_by(LabSession.started_at.desc())
        
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def get_session_by_id(self, session_id: uuid.UUID) -> Optional[LabSession]:
        """Get session by ID"""
        
        query = select(LabSession).where(LabSession.id == session_id)
        result = await self.db.execute(query)
        return result.scalar_one_or_none()
    
    async def get_session_with_details(self, session_id: uuid.UUID) -> Optional[Dict[str, Any]]:
        """Get session with related lab and VM details"""
        
        # Get session with lab info
        query = select(LabSession, Lab).join(Lab).where(LabSession.id == session_id)
        result = await self.db.execute(query)
        session_lab = result.first()
        
        if not session_lab:
            return None
        
        session, lab = session_lab
        
        # Get VM instances
        vm_query = select(VMInstance).where(VMInstance.session_id == session_id)
        vm_result = await self.db.execute(vm_query)
        vms = vm_result.scalars().all()
        
        return {
            "session": session,
            "lab": lab,
            "vm_instances": vms,
            "time_remaining_minutes": session.time_remaining_minutes,
            "is_expired": session.is_expired,
            "connection_info": [vm.connection_info for vm in vms if vm.is_accessible]
        }
    
    async def cleanup_expired_sessions(self) -> int:
        """Cleanup expired sessions (background task)"""
        
        expired_query = select(LabSession).where(
            and_(
                LabSession.expires_at < datetime.utcnow(),
                LabSession.status.in_([
                    SessionStatus.ACTIVE,
                    SessionStatus.PAUSED,
                    SessionStatus.PROVISIONING
                ])
            )
        )
        
        result = await self.db.execute(expired_query)
        expired_sessions = result.scalars().all()
        
        cleanup_count = 0
        for session in expired_sessions:
            try:
                await self.stop_session(session.id)
                cleanup_count += 1
            except Exception as e:
                logger.error(f"Failed to cleanup expired session {session.id}: {e}")
        
        if cleanup_count > 0:
            logger.info(f"Cleaned up {cleanup_count} expired sessions")
        
        return cleanup_count
    
    # Private helper methods
    
    async def _can_user_start_session(self, user: User) -> Tuple[bool, str]:
        """Check if user can start a new session"""
        
        # Check account status
        if not user.is_active:
            return False, "User account is inactive"
        
        # Check concurrent session limit
        active_sessions = await self.get_user_active_sessions(user.id)
        if len(active_sessions) >= user.max_concurrent_sessions:
            return False, f"Maximum concurrent sessions limit reached ({user.max_concurrent_sessions})"
        
        return True, "OK"
    
    async def _allocate_user_network(self, user_id: uuid.UUID) -> str:
        """Allocate a unique network range for user"""
        
        # Simple allocation: use last 2 bytes of user UUID as network ID
        user_bytes = user_id.bytes[-2:]
        network_id = int.from_bytes(user_bytes, 'big') % 65536
        
        # Ensure we don't use reserved ranges
        if network_id < 1:
            network_id = 1
        if network_id > 65534:
            network_id = 65534
        
        return f"10.10.{network_id >> 8}.{network_id & 0xFF}/24"
    
    async def _get_lab_vm_configs(self, lab_id: uuid.UUID) -> List[Dict[str, Any]]:
        """Get VM configurations for a lab"""
        
        query = select(Lab).where(Lab.id == lab_id)
        result = await self.db.execute(query)
        lab = result.scalar_one_or_none()
        
        if not lab or not lab.vm_templates:
            return []
        
        vm_configs = []
        
        # Parse attack boxes
        for attack_box in lab.vm_templates.get("attack_boxes", []):
            vm_configs.append({
                "type": "attack_box",
                "template_id": attack_box.get("template_id"),
                "resources": attack_box.get("resources", {}),
                "os_type": attack_box.get("type", "kali")
            })
        
        # Parse target VMs
        for target in lab.vm_templates.get("targets", []):
            vm_configs.append({
                "type": "target",
                "name": target.get("name"),
                "template_id": target.get("template_id"),
                "ip": target.get("ip"),
                "resources": target.get("resources", {})
            })
        
        return vm_configs
    
    async def _initialize_user_progress(self, user_id: uuid.UUID, lab_id: uuid.UUID):
        """Initialize user progress record if not exists"""
        
        existing_query = select(UserProgress).where(
            and_(
                UserProgress.user_id == user_id,
                UserProgress.lab_id == lab_id
            )
        )
        result = await self.db.execute(existing_query)
        existing = result.scalar_one_or_none()
        
        if not existing:
            progress = UserProgress(
                id=uuid.uuid4(),
                user_id=user_id,
                lab_id=lab_id,
                status=CompletionStatus.IN_PROGRESS,
                first_started_at=datetime.utcnow()
            )
            self.db.add(progress)
            
            # Increment session count
            progress.session_count = 1
            await self.db.commit()
        else:
            # Update existing progress
            existing.session_count += 1
            existing.last_activity_at = datetime.utcnow()
            if existing.status == CompletionStatus.NOT_STARTED:
                existing.status = CompletionStatus.IN_PROGRESS
                existing.first_started_at = datetime.utcnow()
            await self.db.commit()
    
    async def _stop_session_vms(self, session_id: uuid.UUID):
        """Stop all VM instances for a session"""
        
        try:
            # Import VM Service here to avoid circular imports
            from app.services.vm_service import VMService
            vm_service = VMService(self.db)
            
            # Cleanup all VMs for this session
            success = await vm_service._cleanup_session_vms(session_id)
            
            if not success:
                logger.warning(f"VM cleanup may have failed for session {session_id}")
        
        except Exception as e:
            logger.error(f"Failed to cleanup VMs for session {session_id}: {e}")
            # Fallback: just update statuses in database
            update_query = update(VMInstance).where(
                VMInstance.session_id == session_id
            ).values(
                status=VMStatus.STOPPED,
                stopped_at=datetime.utcnow()
            )
            
            await self.db.execute(update_query)
            await self.db.commit()
    
    async def _cleanup_session_network(self, session: LabSession):
        """Cleanup network resources for session"""
        
        try:
            # Import Network Service here to avoid circular imports
            from app.services.network_service import NetworkService
            network_service = NetworkService(self.db)
            
            # Remove user network
            success = await network_service.remove_user_network(
                user_id=session.user_id,
                session_id=session.id
            )
            
            if success:
                logger.info(f"Cleaned up network {session.network_range} for session {session.id}")
            else:
                logger.warning(f"Network cleanup may have failed for session {session.id}")
        
        except Exception as e:
            logger.error(f"Failed to cleanup network for session {session.id}: {e}")
    
    async def _update_session_time_spent(self, session: LabSession):
        """Update user progress with session duration"""
        
        if not session.started_at or not session.stopped_at:
            return
        
        duration_minutes = int((session.stopped_at - session.started_at).total_seconds() / 60)
        
        # Update user progress
        progress_query = select(UserProgress).where(
            and_(
                UserProgress.user_id == session.user_id,
                UserProgress.lab_id == session.lab_id
            )
        )
        result = await self.db.execute(progress_query)
        progress = result.scalar_one_or_none()
        
        if progress:
            progress.total_time_spent_minutes += duration_minutes
            progress.last_activity_at = datetime.utcnow()
            await self.db.commit()
    
    async def _calculate_session_duration_minutes(self, session: LabSession) -> int:
        """Calculate session duration in minutes"""
        
        if not session.started_at:
            return 0
        
        end_time = session.stopped_at or datetime.utcnow()
        return int((end_time - session.started_at).total_seconds() / 60)
    
    async def _cache_session(self, session: LabSession):
        """Cache session data in Redis"""
        
        session_data = {
            "id": str(session.id),
            "user_id": str(session.user_id),
            "lab_id": str(session.lab_id),
            "status": session.status,
            "network_range": session.network_range,
            "expires_at": session.expires_at.isoformat(),
            "access_method": session.access_method
        }
        
        cache_key = f"lab_session:{session.id}"
        await redis_client.set(cache_key, session_data, expire=3600)  # 1 hour
    
    async def _remove_session_from_cache(self, session_id: uuid.UUID):
        """Remove session from cache"""
        
        cache_key = f"lab_session:{session_id}"
        await redis_client.delete(cache_key)
    
    async def _log_session_event(self, session: LabSession, event_type: str, data: Dict[str, Any]):
        """Log session event to session logs"""
        
        if not session.session_logs:
            session.session_logs = []
        
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "data": data
        }
        
        session.session_logs.append(event)
        
        # Keep only last 100 events
        if len(session.session_logs) > 100:
            session.session_logs = session.session_logs[-100:]
        
        # Mark the attribute as modified for SQLAlchemy
        session.session_logs = session.session_logs.copy()
        await self.db.commit()
