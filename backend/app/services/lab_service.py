"""
Lab service for lab management operations
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func
from typing import Optional, List, Dict, Any
import uuid

from app.models.lab import Lab, LabCategory, DifficultyLevel, LabStatus
from app.models.user import User
from app.models.progress import UserProgress, CompletionStatus


class LabService:
    """Service class for lab operations"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def get_all_labs(
        self,
        user: User,
        category_id: Optional[uuid.UUID] = None,
        difficulty: Optional[str] = None,
        search: Optional[str] = None,
        tags: Optional[List[str]] = None,
        skip: int = 0,
        limit: int = 50,
        include_progress: bool = True
    ) -> Dict[str, Any]:
        """Get labs with filtering, pagination, and user progress"""
        
        # Build base query
        query = select(Lab).where(Lab.is_published == True)
        
        # Apply filters
        if category_id:
            query = query.where(Lab.category_id == category_id)
        
        if difficulty:
            query = query.where(Lab.difficulty == difficulty)
        
        # Subscription-based filtering
        if not user.is_premium:
            query = query.where(Lab.requires_subscription == False)
        
        # Search functionality
        if search:
            search_term = f"%{search.lower()}%"
            query = query.where(
                or_(
                    Lab.name.ilike(search_term),
                    Lab.description.ilike(search_term),
                    Lab.short_description.ilike(search_term),
                    Lab.tags.op('@>')([search.lower()])  # Tag search
                )
            )
        
        # Tag filtering
        if tags:
            for tag in tags:
                query = query.where(Lab.tags.op('@>')([tag.lower()]))
        
        # Count total results
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await self.db.execute(count_query)
        total = total_result.scalar()
        
        # Apply pagination and ordering
        query = query.order_by(Lab.name).offset(skip).limit(limit)
        
        # Execute query
        result = await self.db.execute(query)
        labs = result.scalars().all()
        
        # Get user progress if requested
        lab_progress = {}
        if include_progress and labs:
            lab_ids = [lab.id for lab in labs]
            progress_query = select(UserProgress).where(
                and_(
                    UserProgress.user_id == user.id,
                    UserProgress.lab_id.in_(lab_ids)
                )
            )
            progress_result = await self.db.execute(progress_query)
            progress_records = progress_result.scalars().all()
            
            lab_progress = {
                progress.lab_id: progress for progress in progress_records
            }
        
        return {
            "labs": labs,
            "lab_progress": lab_progress,
            "total": total,
            "page": skip // limit + 1 if limit > 0 else 1,
            "pages": (total + limit - 1) // limit if limit > 0 else 1,
            "has_next": skip + limit < total,
            "has_prev": skip > 0
        }
    
    async def get_lab_by_id(self, lab_id: uuid.UUID, user: User) -> Optional[Lab]:
        """Get lab by ID with permission checks"""
        
        query = select(Lab).where(
            and_(
                Lab.id == lab_id,
                Lab.is_published == True
            )
        )
        
        result = await self.db.execute(query)
        lab = result.scalar_one_or_none()
        
        if not lab:
            return None
        
        # Check subscription requirements
        if lab.requires_subscription and not user.is_premium:
            return None
        
        return lab
    
    async def get_lab_by_slug(self, slug: str, user: User) -> Optional[Lab]:
        """Get lab by slug with permission checks"""
        
        query = select(Lab).where(
            and_(
                Lab.slug == slug,
                Lab.is_published == True
            )
        )
        
        result = await self.db.execute(query)
        lab = result.scalar_one_or_none()
        
        if not lab:
            return None
        
        # Check subscription requirements
        if lab.requires_subscription and not user.is_premium:
            return None
        
        return lab
    
    async def get_user_lab_progress(self, user_id: uuid.UUID, lab_id: uuid.UUID) -> Optional[UserProgress]:
        """Get user's progress for a specific lab"""
        
        query = select(UserProgress).where(
            and_(
                UserProgress.user_id == user_id,
                UserProgress.lab_id == lab_id
            )
        )
        
        result = await self.db.execute(query)
        return result.scalar_one_or_none()
    
    async def get_all_categories(self) -> List[LabCategory]:
        """Get all lab categories ordered by sort_order"""
        
        query = select(LabCategory).order_by(LabCategory.sort_order, LabCategory.name)
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def get_category_by_slug(self, slug: str) -> Optional[LabCategory]:
        """Get category by slug"""
        
        query = select(LabCategory).where(LabCategory.slug == slug)
        result = await self.db.execute(query)
        return result.scalar_one_or_none()
    
    async def get_labs_by_category(
        self,
        category_id: uuid.UUID,
        user: User,
        skip: int = 0,
        limit: int = 50
    ) -> Dict[str, Any]:
        """Get labs in a specific category"""
        
        return await self.get_all_labs(
            user=user,
            category_id=category_id,
            skip=skip,
            limit=limit
        )
    
    async def search_labs(
        self,
        search_term: str,
        user: User,
        skip: int = 0,
        limit: int = 50
    ) -> Dict[str, Any]:
        """Search labs by name, description, or tags"""
        
        return await self.get_all_labs(
            user=user,
            search=search_term,
            skip=skip,
            limit=limit
        )
    
    async def get_featured_labs(self, user: User, limit: int = 10) -> List[Lab]:
        """Get featured/recommended labs"""
        
        query = select(Lab).where(
            and_(
                Lab.is_published == True,
                Lab.is_featured == True
            )
        )
        
        # Apply subscription filter
        if not user.is_premium:
            query = query.where(Lab.requires_subscription == False)
        
        query = query.order_by(Lab.average_rating.desc()).limit(limit)
        
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def get_beginner_labs(self, user: User, limit: int = 10) -> List[Lab]:
        """Get beginner-friendly labs"""
        
        query = select(Lab).where(
            and_(
                Lab.is_published == True,
                Lab.difficulty == DifficultyLevel.BEGINNER
            )
        )
        
        # Apply subscription filter
        if not user.is_premium:
            query = query.where(Lab.requires_subscription == False)
        
        query = query.order_by(Lab.completion_count.desc()).limit(limit)
        
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def get_lab_statistics(self, lab_id: uuid.UUID) -> Dict[str, Any]:
        """Get statistics for a specific lab"""
        
        # Get lab
        lab = await self.get_lab_by_id_raw(lab_id)
        if not lab:
            return {}
        
        # Get progress statistics
        progress_query = select(
            func.count(UserProgress.id).label('total_attempts'),
            func.count().filter(UserProgress.status == CompletionStatus.COMPLETED).label('completions'),
            func.avg(UserProgress.total_time_spent_minutes).label('avg_time_minutes'),
            func.avg(UserProgress.user_rating).label('avg_rating')
        ).where(UserProgress.lab_id == lab_id)
        
        result = await self.db.execute(progress_query)
        stats = result.first()
        
        completion_rate = 0
        if stats.total_attempts > 0:
            completion_rate = (stats.completions / stats.total_attempts) * 100
        
        return {
            "total_attempts": stats.total_attempts or 0,
            "total_completions": stats.completions or 0,
            "completion_rate": round(completion_rate, 2),
            "average_completion_time_hours": round((stats.avg_time_minutes or 0) / 60, 2),
            "average_rating": round(stats.avg_rating or 0, 2)
        }
    
    async def get_lab_by_id_raw(self, lab_id: uuid.UUID) -> Optional[Lab]:
        """Get lab by ID without permission checks (for admin/internal use)"""
        
        query = select(Lab).where(Lab.id == lab_id)
        result = await self.db.execute(query)
        return result.scalar_one_or_none()
    
    async def can_user_access_lab(self, user: User, lab: Lab) -> tuple[bool, str]:
        """Check if user can access a specific lab"""
        
        # Check if lab is published
        if not lab.is_published:
            return False, "Lab is not available"
        
        # Check subscription requirements
        if lab.requires_subscription and not user.is_premium:
            return False, "Premium subscription required"
        
        # Check if user account is active
        if not user.is_active:
            return False, "User account is inactive"
        
        return True, "Access granted"
    
    async def get_lab_with_progress(
        self, 
        lab_id: uuid.UUID, 
        user: User
    ) -> Optional[Dict[str, Any]]:
        """Get lab details with user's progress information"""
        
        lab = await self.get_lab_by_id(lab_id, user)
        if not lab:
            return None
        
        # Get user's progress
        progress = await self.get_user_lab_progress(user.id, lab_id)
        
        # Get lab statistics
        stats = await self.get_lab_statistics(lab_id)
        
        return {
            "lab": lab,
            "user_progress": progress,
            "statistics": stats,
            "can_access": await self.can_user_access_lab(user, lab)
        }
    
    async def increment_lab_completion(self, lab_id: uuid.UUID):
        """Increment lab completion count (called when user completes lab)"""
        
        from sqlalchemy import update
        
        await self.db.execute(
            update(Lab)
            .where(Lab.id == lab_id)
            .values(completion_count=Lab.completion_count + 1)
        )
        await self.db.commit()
    
    async def update_lab_rating(self, lab_id: uuid.UUID):
        """Recalculate lab average rating"""
        
        # Get all ratings for this lab
        rating_query = select(
            func.avg(UserProgress.user_rating).label('avg_rating'),
            func.count(UserProgress.user_rating).label('rating_count')
        ).where(
            and_(
                UserProgress.lab_id == lab_id,
                UserProgress.user_rating.isnot(None)
            )
        )
        
        result = await self.db.execute(rating_query)
        stats = result.first()
        
        if stats.rating_count > 0:
            from sqlalchemy import update
            
            await self.db.execute(
                update(Lab)
                .where(Lab.id == lab_id)
                .values(average_rating=round(stats.avg_rating, 1))
            )
            await self.db.commit()
