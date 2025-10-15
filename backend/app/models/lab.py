"""
Lab models for managing cybersecurity training labs
"""

from sqlalchemy import Column, String, Text, Integer, Boolean, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from enum import Enum
import uuid

from app.core.database import Base


class DifficultyLevel(str, Enum):
    """Lab difficulty levels"""
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate" 
    ADVANCED = "advanced"
    EXPERT = "expert"


class LabStatus(str, Enum):
    """Lab status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    MAINTENANCE = "maintenance"
    DEPRECATED = "deprecated"


class LabCategory(Base):
    """Lab categories (Web Apps, Active Directory, etc.)"""
    
    __tablename__ = "lab_categories"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), unique=True, nullable=False)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text)
    icon = Column(String(100))  # Icon name/class
    color = Column(String(7))   # Hex color code
    sort_order = Column(Integer, default=0)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationships
    labs = relationship("Lab", back_populates="category")


class Lab(Base):
    """Cybersecurity lab/challenge definition"""
    
    __tablename__ = "labs"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Basic info
    name = Column(String(255), nullable=False)
    slug = Column(String(255), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=False)
    short_description = Column(String(500))
    
    # Lab metadata
    difficulty = Column(String(20), nullable=False)  # DifficultyLevel enum
    estimated_time_hours = Column(Integer, default=2)
    points = Column(Integer, default=10)
    status = Column(String(20), default=LabStatus.ACTIVE)
    
    # Category relationship
    category_id = Column(UUID(as_uuid=True), ForeignKey("lab_categories.id"))
    category = relationship("LabCategory", back_populates="labs")
    
    # Lab content
    objectives = Column(ARRAY(Text))  # Learning objectives
    prerequisites = Column(ARRAY(Text))  # Required knowledge
    tags = Column(ARRAY(String(50)))  # Tags for search/filtering
    
    # VM Configuration
    vm_templates = Column(JSONB)  # VM template configurations
    """
    Example vm_templates structure:
    {
        "attack_boxes": [
            {"type": "kali", "template_id": "kali-2023.4", "resources": {"cpu": 2, "ram": 4096}},
            {"type": "windows", "template_id": "win10-pentest", "resources": {"cpu": 2, "ram": 4096}}
        ],
        "targets": [
            {"name": "web-server", "template_id": "ubuntu-lamp", "ip": "10.10.1.100"},
            {"name": "dc", "template_id": "win2019-dc", "ip": "10.10.1.101"}
        ]
    }
    """
    
    # Network configuration
    network_config = Column(JSONB)
    """
    Example network_config:
    {
        "user_network": "10.10.{user_id}.0/24",
        "vpn_enabled": true,
        "guacamole_enabled": true,
        "required_ports": [80, 443, 445, 3389],
        "firewall_rules": [...]
    }
    """
    
    # Flags and completion criteria
    flags = Column(JSONB)  # Expected flags for completion
    """
    Example flags structure:
    {
        "user_flag": "HTB{user_flag_hash}",
        "root_flag": "HTB{root_flag_hash}",
        "custom_flags": [
            {"name": "web_shell", "value": "HTB{web_shell_flag}", "points": 5},
            {"name": "privilege_escalation", "value": "HTB{privesc_flag}", "points": 10}
        ]
    }
    """
    
    # Documentation and hints
    writeup_url = Column(String(500))  # Link to official writeup
    hints = Column(JSONB)  # Progressive hints system
    """
    Example hints structure:
    {
        "hints": [
            {"level": 1, "content": "Look for common web vulnerabilities", "cost": 0},
            {"level": 2, "content": "Check for SQL injection in login form", "cost": 5},
            {"level": 3, "content": "Use sqlmap with --dump parameter", "cost": 10}
        ]
    }
    """
    
    # Statistics and metrics
    completion_count = Column(Integer, default=0)
    average_completion_time_hours = Column(Integer)
    average_rating = Column(Integer)  # 1-5 star rating
    
    # Lab availability
    is_published = Column(Boolean, default=False)
    is_featured = Column(Boolean, default=False)
    requires_subscription = Column(Boolean, default=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    published_at = Column(DateTime(timezone=True))
    
    # Content management
    created_by = Column(UUID(as_uuid=True))  # Admin user who created the lab
    
    def __repr__(self):
        return f"<Lab(id={self.id}, name='{self.name}', difficulty='{self.difficulty}')>"
    
    @property
    def is_beginner_friendly(self) -> bool:
        """Check if lab is suitable for beginners"""
        return self.difficulty == DifficultyLevel.BEGINNER
    
    @property
    def total_flags(self) -> int:
        """Get total number of flags in this lab"""
        if not self.flags:
            return 0
        
        count = 0
        if self.flags.get("user_flag"):
            count += 1
        if self.flags.get("root_flag"):
            count += 1
        if self.flags.get("custom_flags"):
            count += len(self.flags["custom_flags"])
        
        return count
    
    @property
    def total_points(self) -> int:
        """Get total points available in this lab"""
        if not self.flags:
            return self.points
        
        total = self.points  # Base points
        
        # Add custom flag points
        if self.flags.get("custom_flags"):
            for flag in self.flags["custom_flags"]:
                total += flag.get("points", 0)
        
        return total
