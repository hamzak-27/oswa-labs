"""
User progress tracking models
"""

from sqlalchemy import Column, String, DateTime, ForeignKey, Integer, Boolean, Text
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from enum import Enum
from datetime import datetime
import uuid

from app.core.database import Base


class FlagType(str, Enum):
    """Types of flags in labs"""
    USER = "user"
    ROOT = "root" 
    CUSTOM = "custom"


class CompletionStatus(str, Enum):
    """Lab completion status"""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    PARTIALLY_COMPLETED = "partially_completed"


class UserProgress(Base):
    """Track user's progress through labs"""
    
    __tablename__ = "user_progress"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Relationships
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    lab_id = Column(UUID(as_uuid=True), ForeignKey("labs.id"), nullable=False)
    
    # Progress tracking
    status = Column(String(20), default=CompletionStatus.NOT_STARTED)
    completion_percentage = Column(Integer, default=0)  # 0-100
    points_earned = Column(Integer, default=0)
    
    # Flag tracking
    flags_found = Column(JSONB, default=dict)
    """
    Example flags_found structure:
    {
        "user_flag": {
            "found": true,
            "submitted_at": "2023-12-01T10:30:00Z",
            "points": 10
        },
        "root_flag": {
            "found": true, 
            "submitted_at": "2023-12-01T11:45:00Z",
            "points": 20
        },
        "custom_flags": {
            "web_shell": {
                "found": true,
                "submitted_at": "2023-12-01T10:15:00Z", 
                "points": 5
            }
        }
    }
    """
    
    # Time tracking
    total_time_spent_minutes = Column(Integer, default=0)
    first_started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    last_activity_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Hints and assistance
    hints_used = Column(JSONB, default=list)  # List of hint IDs used
    hint_penalty_points = Column(Integer, default=0)
    
    # Attempts and resets
    lab_resets_count = Column(Integer, default=0)
    session_count = Column(Integer, default=0)  # Number of sessions started
    
    # Rating and feedback
    user_rating = Column(Integer)  # 1-5 stars
    user_feedback = Column(Text)
    difficulty_rating = Column(Integer)  # How difficult user found it (1-5)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Additional metadata
    user_metadata = Column(JSONB, default=dict)  # Extra tracking data
    
    def __repr__(self):
        return f"<UserProgress(user_id={self.user_id}, lab_id={self.lab_id}, status='{self.status}')>"
    
    @property
    def is_completed(self) -> bool:
        """Check if lab is completed"""
        return self.status == CompletionStatus.COMPLETED
    
    @property
    def flags_found_count(self) -> int:
        """Count of flags found"""
        if not self.flags_found:
            return 0
        
        count = 0
        
        # Count main flags
        if self.flags_found.get("user_flag", {}).get("found"):
            count += 1
        if self.flags_found.get("root_flag", {}).get("found"):
            count += 1
        
        # Count custom flags
        custom_flags = self.flags_found.get("custom_flags", {})
        for flag_data in custom_flags.values():
            if flag_data.get("found"):
                count += 1
        
        return count
    
    def add_flag(self, flag_type: str, flag_name: str = None, points: int = 0):
        """Add a found flag to progress"""
        if not self.flags_found:
            self.flags_found = {}
        
        timestamp = datetime.utcnow().isoformat()
        
        if flag_type in ["user", "root"]:
            key = f"{flag_type}_flag"
            self.flags_found[key] = {
                "found": True,
                "submitted_at": timestamp,
                "points": points
            }
        else:  # custom flag
            if "custom_flags" not in self.flags_found:
                self.flags_found["custom_flags"] = {}
            
            self.flags_found["custom_flags"][flag_name] = {
                "found": True,
                "submitted_at": timestamp,
                "points": points
            }
        
        # Update points and completion
        self.points_earned += points
        self.last_activity_at = datetime.utcnow()
    
    def calculate_completion_percentage(self, total_flags: int) -> int:
        """Calculate completion percentage based on flags found"""
        if total_flags == 0:
            return 100
        
        found_count = self.flags_found_count
        return min(100, int((found_count / total_flags) * 100))


class SubmittedFlag(Base):
    """Track individual flag submissions (for audit trail)"""
    
    __tablename__ = "submitted_flags"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Relationships
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    lab_id = Column(UUID(as_uuid=True), ForeignKey("labs.id"), nullable=False)
    progress_id = Column(UUID(as_uuid=True), ForeignKey("user_progress.id"))
    
    # Flag details
    flag_type = Column(String(20), nullable=False)  # user, root, custom
    flag_name = Column(String(100))  # For custom flags
    submitted_value = Column(String(255), nullable=False)
    expected_value = Column(String(255), nullable=False)
    is_correct = Column(Boolean, nullable=False)
    
    # Points and scoring
    points_awarded = Column(Integer, default=0)
    
    # Submission context
    submission_ip = Column(String(15))  # User's IP address
    user_agent = Column(String(500))    # Browser user agent
    session_id = Column(UUID(as_uuid=True))  # Related lab session
    
    # Timestamps
    submitted_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Additional data
    submission_metadata = Column(JSONB, default=dict)  # Extra submission data
    
    def __repr__(self):
        return f"<SubmittedFlag(user_id={self.user_id}, flag_type='{self.flag_type}', correct={self.is_correct})>"
