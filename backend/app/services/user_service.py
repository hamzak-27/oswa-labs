"""
User service for user management operations
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete
from typing import Optional, List
import uuid

from app.models.user import User
from app.core.security import get_password_hash


class UserService:
    """Service class for user operations"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def create(self, user: User) -> User:
        """Create a new user"""
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)
        return user
    
    async def get_by_id(self, user_id: uuid.UUID) -> Optional[User]:
        """Get user by ID"""
        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        return result.scalar_one_or_none()
    
    async def get_by_username(self, username: str) -> Optional[User]:
        """Get user by username"""
        result = await self.db.execute(
            select(User).where(User.username == username.lower())
        )
        return result.scalar_one_or_none()
    
    async def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email"""
        result = await self.db.execute(
            select(User).where(User.email == email.lower())
        )
        return result.scalar_one_or_none()
    
    async def update(self, user: User) -> User:
        """Update user"""
        await self.db.commit()
        await self.db.refresh(user)
        return user
    
    async def update_password(self, user_id: uuid.UUID, new_password: str) -> bool:
        """Update user password"""
        password_hash = get_password_hash(new_password)
        
        result = await self.db.execute(
            update(User)
            .where(User.id == user_id)
            .values(password_hash=password_hash)
        )
        
        await self.db.commit()
        return result.rowcount > 0
    
    async def update_last_login(self, user_id: uuid.UUID) -> bool:
        """Update user's last login timestamp"""
        from datetime import datetime
        
        result = await self.db.execute(
            update(User)
            .where(User.id == user_id)
            .values(last_login=datetime.utcnow())
        )
        
        await self.db.commit()
        return result.rowcount > 0
    
    async def activate_user(self, user_id: uuid.UUID) -> bool:
        """Activate user account"""
        result = await self.db.execute(
            update(User)
            .where(User.id == user_id)
            .values(is_active=True)
        )
        
        await self.db.commit()
        return result.rowcount > 0
    
    async def deactivate_user(self, user_id: uuid.UUID) -> bool:
        """Deactivate user account"""
        result = await self.db.execute(
            update(User)
            .where(User.id == user_id)
            .values(is_active=False)
        )
        
        await self.db.commit()
        return result.rowcount > 0
    
    async def verify_email(self, user_id: uuid.UUID) -> bool:
        """Mark user email as verified"""
        from datetime import datetime
        
        result = await self.db.execute(
            update(User)
            .where(User.id == user_id)
            .values(
                is_verified=True,
                email_verified_at=datetime.utcnow()
            )
        )
        
        await self.db.commit()
        return result.rowcount > 0
    
    async def update_subscription(self, user_id: uuid.UUID, tier: str, max_sessions: int = None) -> bool:
        """Update user subscription tier"""
        update_data = {"subscription_tier": tier}
        
        if max_sessions is not None:
            update_data["max_concurrent_sessions"] = max_sessions
        
        result = await self.db.execute(
            update(User)
            .where(User.id == user_id)
            .values(**update_data)
        )
        
        await self.db.commit()
        return result.rowcount > 0
    
    async def get_all_users(
        self, 
        skip: int = 0, 
        limit: int = 100, 
        active_only: bool = True
    ) -> List[User]:
        """Get all users with pagination"""
        query = select(User)
        
        if active_only:
            query = query.where(User.is_active == True)
        
        query = query.offset(skip).limit(limit).order_by(User.created_at.desc())
        
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def get_user_count(self, active_only: bool = True) -> int:
        """Get total user count"""
        from sqlalchemy import func
        
        query = select(func.count(User.id))
        
        if active_only:
            query = query.where(User.is_active == True)
        
        result = await self.db.execute(query)
        return result.scalar()
    
    async def search_users(
        self, 
        search_term: str, 
        skip: int = 0, 
        limit: int = 50
    ) -> List[User]:
        """Search users by username or email"""
        search_pattern = f"%{search_term.lower()}%"
        
        query = select(User).where(
            (User.username.ilike(search_pattern)) |
            (User.email.ilike(search_pattern)) |
            (User.first_name.ilike(search_pattern)) |
            (User.last_name.ilike(search_pattern))
        ).offset(skip).limit(limit).order_by(User.username)
        
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def delete_user(self, user_id: uuid.UUID) -> bool:
        """Delete user (soft delete by deactivating)"""
        return await self.deactivate_user(user_id)
    
    async def hard_delete_user(self, user_id: uuid.UUID) -> bool:
        """Hard delete user (permanent deletion)"""
        result = await self.db.execute(
            delete(User).where(User.id == user_id)
        )
        
        await self.db.commit()
        return result.rowcount > 0
