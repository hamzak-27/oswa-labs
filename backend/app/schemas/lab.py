"""
Lab schemas for API request/response validation
"""

from pydantic import BaseModel, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid

from app.models.lab import DifficultyLevel, LabStatus


class LabCategoryResponse(BaseModel):
    """Lab category response schema"""
    id: uuid.UUID
    name: str
    slug: str
    description: Optional[str]
    icon: Optional[str]
    color: Optional[str]
    sort_order: int
    lab_count: Optional[int] = 0  # Will be populated if requested
    
    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "name": "Web Application Security",
                "slug": "web-apps",
                "description": "Penetration testing of web applications",
                "icon": "web",
                "color": "#3498db",
                "sort_order": 1,
                "lab_count": 15
            }
        }


class LabSummaryResponse(BaseModel):
    """Lab summary response for listing"""
    id: uuid.UUID
    name: str
    slug: str
    short_description: Optional[str]
    difficulty: str
    estimated_time_hours: int
    points: int
    completion_count: int
    average_rating: Optional[int]
    is_featured: bool
    requires_subscription: bool
    tags: Optional[List[str]] = []
    category: Optional[LabCategoryResponse]
    
    # User progress (if included)
    user_progress: Optional[Dict[str, Any]] = None
    
    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "name": "SQL Injection Playground",
                "slug": "sql-injection-playground",
                "short_description": "Practice SQL injection on a vulnerable web application",
                "difficulty": "beginner",
                "estimated_time_hours": 2,
                "points": 20,
                "completion_count": 1250,
                "average_rating": 4,
                "is_featured": True,
                "requires_subscription": False,
                "tags": ["sql-injection", "web-security", "database"],
                "category": {
                    "name": "Web Application Security",
                    "slug": "web-apps"
                }
            }
        }


class VMTemplateResponse(BaseModel):
    """VM template configuration response"""
    type: str
    template_id: str
    resources: Dict[str, Any]
    name: Optional[str] = None
    ip: Optional[str] = None


class NetworkConfigResponse(BaseModel):
    """Network configuration response"""
    user_network: str
    vpn_enabled: bool
    guacamole_enabled: bool
    required_ports: List[int]


class FlagResponse(BaseModel):
    """Flag information response"""
    user_flag: Optional[str] = None
    root_flag: Optional[str] = None
    custom_flags: Optional[List[Dict[str, Any]]] = []


class HintResponse(BaseModel):
    """Hint response"""
    level: int
    content: str
    cost: int


class LabProgressResponse(BaseModel):
    """User's progress on a specific lab"""
    status: str
    completion_percentage: int
    points_earned: int
    flags_found_count: int
    total_time_spent_hours: float
    hints_used_count: int
    hint_penalty_points: int
    user_rating: Optional[int]
    first_started_at: Optional[datetime]
    completed_at: Optional[datetime]
    last_activity_at: datetime
    
    class Config:
        from_attributes = True


class LabStatisticsResponse(BaseModel):
    """Lab statistics response"""
    total_attempts: int
    total_completions: int
    completion_rate: float
    average_completion_time_hours: float
    average_rating: float


class LabDetailResponse(BaseModel):
    """Detailed lab information response"""
    id: uuid.UUID
    name: str
    slug: str
    description: str
    short_description: Optional[str]
    difficulty: str
    estimated_time_hours: int
    points: int
    status: str
    
    # Category
    category: Optional[LabCategoryResponse]
    
    # Lab content
    objectives: List[str]
    prerequisites: List[str]
    tags: List[str]
    
    # Configuration (sanitized for users)
    vm_templates: Dict[str, Any]
    network_config: Dict[str, Any]
    
    # Hints (without solutions)
    hints_available: int
    
    # Statistics
    completion_count: int
    average_completion_time_hours: Optional[int]
    average_rating: Optional[int]
    
    # Status flags
    is_featured: bool
    requires_subscription: bool
    
    # Timestamps
    created_at: datetime
    updated_at: datetime
    published_at: Optional[datetime]
    
    # User-specific data (if user is authenticated)
    user_progress: Optional[LabProgressResponse] = None
    can_access: bool = True
    access_message: str = "Access granted"
    
    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "name": "SQL Injection Playground",
                "slug": "sql-injection-playground",
                "description": "Learn and practice SQL injection techniques...",
                "short_description": "Practice SQL injection on a vulnerable web application",
                "difficulty": "beginner",
                "estimated_time_hours": 2,
                "points": 20,
                "category": {
                    "name": "Web Application Security",
                    "slug": "web-apps"
                },
                "objectives": [
                    "Understand SQL injection vulnerabilities",
                    "Learn different injection techniques"
                ],
                "prerequisites": [
                    "Basic SQL knowledge",
                    "Understanding of web applications"
                ],
                "tags": ["sql-injection", "web-security"],
                "hints_available": 3,
                "completion_count": 1250,
                "average_rating": 4,
                "requires_subscription": False
            }
        }


class LabListResponse(BaseModel):
    """Paginated lab list response"""
    labs: List[LabSummaryResponse]
    total: int
    page: int
    pages: int
    has_next: bool
    has_prev: bool
    
    class Config:
        json_schema_extra = {
            "example": {
                "labs": [
                    {
                        "name": "SQL Injection Playground",
                        "difficulty": "beginner",
                        "points": 20
                    }
                ],
                "total": 25,
                "page": 1,
                "pages": 3,
                "has_next": True,
                "has_prev": False
            }
        }


class CategoryWithLabsResponse(BaseModel):
    """Category with lab count response"""
    id: uuid.UUID
    name: str
    slug: str
    description: Optional[str]
    icon: Optional[str]
    color: Optional[str]
    sort_order: int
    lab_count: int
    
    class Config:
        from_attributes = True


class LabSearchRequest(BaseModel):
    """Lab search request schema"""
    query: str
    category: Optional[str] = None
    difficulty: Optional[str] = None
    tags: Optional[List[str]] = []
    
    @validator("difficulty")
    def validate_difficulty(cls, v):
        if v and v not in [d.value for d in DifficultyLevel]:
            raise ValueError(f"Invalid difficulty. Must be one of: {', '.join([d.value for d in DifficultyLevel])}")
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "query": "web application",
                "category": "web-apps",
                "difficulty": "beginner",
                "tags": ["sql-injection", "xss"]
            }
        }


class LabFiltersResponse(BaseModel):
    """Available lab filters response"""
    categories: List[CategoryWithLabsResponse]
    difficulties: List[str]
    all_tags: List[str]
    
    class Config:
        json_schema_extra = {
            "example": {
                "categories": [
                    {
                        "name": "Web Application Security",
                        "slug": "web-apps",
                        "lab_count": 15
                    }
                ],
                "difficulties": ["beginner", "intermediate", "advanced", "expert"],
                "all_tags": ["sql-injection", "xss", "privilege-escalation", "buffer-overflow"]
            }
        }
