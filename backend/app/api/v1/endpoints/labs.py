"""
Labs API endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, distinct
from typing import List, Optional
import uuid

from app.core.database import get_db
from app.models.user import User
from app.models.lab import Lab, LabCategory, DifficultyLevel
from app.api.v1.endpoints.auth import get_current_user_dependency
from app.services.lab_service import LabService
from app.schemas.lab import (
    LabListResponse,
    LabDetailResponse,
    LabSummaryResponse,
    LabCategoryResponse,
    LabProgressResponse,
    LabStatisticsResponse,
    LabFiltersResponse,
    CategoryWithLabsResponse
)
from loguru import logger

router = APIRouter()


@router.get("/", response_model=LabListResponse)
async def get_labs(
    category: Optional[str] = Query(None, description="Filter by category slug"),
    difficulty: Optional[str] = Query(None, description="Filter by difficulty level"),
    search: Optional[str] = Query(None, description="Search labs by name, description, or tags"),
    tags: Optional[str] = Query(None, description="Comma-separated list of tags to filter by"),
    featured_only: bool = Query(False, description="Show only featured labs"),
    skip: int = Query(0, ge=0, description="Number of labs to skip"),
    limit: int = Query(50, ge=1, le=100, description="Number of labs to return"),
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Get available labs with filtering and pagination"""
    
    lab_service = LabService(db)
    
    # Parse tags if provided
    tag_list = [tag.strip() for tag in tags.split(",")] if tags else None
    
    # Convert category slug to category_id if provided
    category_id = None
    if category:
        category_obj = await lab_service.get_category_by_slug(category)
        if not category_obj:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Category not found"
            )
        category_id = category_obj.id
    
    # Validate difficulty if provided
    if difficulty and difficulty not in [d.value for d in DifficultyLevel]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid difficulty. Must be one of: {', '.join([d.value for d in DifficultyLevel])}"
        )
    
    # Get featured labs if requested
    if featured_only:
        labs = await lab_service.get_featured_labs(current_user, limit)
        return LabListResponse(
            labs=[LabSummaryResponse.from_orm(lab) for lab in labs],
            total=len(labs),
            page=1,
            pages=1,
            has_next=False,
            has_prev=False
        )
    
    # Get labs with filters
    result = await lab_service.get_all_labs(
        user=current_user,
        category_id=category_id,
        difficulty=difficulty,
        search=search,
        tags=tag_list,
        skip=skip,
        limit=limit,
        include_progress=True
    )
    
    # Convert to response format
    lab_summaries = []
    for lab in result["labs"]:
        lab_summary = LabSummaryResponse.from_orm(lab)
        
        # Add user progress if available
        if lab.id in result["lab_progress"]:
            progress = result["lab_progress"][lab.id]
            lab_summary.user_progress = {
                "status": progress.status,
                "completion_percentage": progress.completion_percentage,
                "points_earned": progress.points_earned,
                "flags_found_count": progress.flags_found_count
            }
        
        lab_summaries.append(lab_summary)
    
    return LabListResponse(
        labs=lab_summaries,
        total=result["total"],
        page=result["page"],
        pages=result["pages"],
        has_next=result["has_next"],
        has_prev=result["has_prev"]
    )


@router.get("/categories", response_model=List[LabCategoryResponse])
async def get_categories(
    include_lab_count: bool = Query(False, description="Include lab count for each category"),
    db: AsyncSession = Depends(get_db)
):
    """Get all lab categories"""
    
    lab_service = LabService(db)
    categories = await lab_service.get_all_categories()
    
    category_responses = []
    for category in categories:
        category_response = LabCategoryResponse.from_orm(category)
        
        # Add lab count if requested
        if include_lab_count:
            count_query = select(func.count(Lab.id)).where(
                Lab.category_id == category.id,
                Lab.is_published == True
            )
            count_result = await db.execute(count_query)
            category_response.lab_count = count_result.scalar()
        
        category_responses.append(category_response)
    
    return category_responses


@router.get("/filters", response_model=LabFiltersResponse)
async def get_lab_filters(
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Get available filter options for labs"""
    
    lab_service = LabService(db)
    
    # Get categories with lab counts
    categories = await lab_service.get_all_categories()
    category_responses = []
    
    for category in categories:
        # Count labs in this category that user can access
        count_query = select(func.count(Lab.id)).where(
            Lab.category_id == category.id,
            Lab.is_published == True
        )
        
        # Apply subscription filter for regular users
        if not current_user.is_premium:
            count_query = count_query.where(Lab.requires_subscription == False)
        
        count_result = await db.execute(count_query)
        lab_count = count_result.scalar()
        
        if lab_count > 0:  # Only include categories with accessible labs
            category_responses.append(CategoryWithLabsResponse(
                id=category.id,
                name=category.name,
                slug=category.slug,
                description=category.description,
                icon=category.icon,
                color=category.color,
                sort_order=category.sort_order,
                lab_count=lab_count
            ))
    
    # Get available difficulties
    difficulties = [d.value for d in DifficultyLevel]
    
    # Get all unique tags from published labs
    tag_query = select(distinct(func.unnest(Lab.tags))).where(Lab.is_published == True)
    if not current_user.is_premium:
        tag_query = tag_query.where(Lab.requires_subscription == False)
    
    tag_result = await db.execute(tag_query)
    all_tags = [tag for tag in tag_result.scalars().all() if tag]
    
    return LabFiltersResponse(
        categories=category_responses,
        difficulties=difficulties,
        all_tags=sorted(all_tags)
    )


@router.get("/{lab_id}", response_model=LabDetailResponse)
async def get_lab(
    lab_id: uuid.UUID,
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Get detailed lab information by ID"""
    
    lab_service = LabService(db)
    
    # Get lab with progress and statistics
    lab_data = await lab_service.get_lab_with_progress(lab_id, current_user)
    
    if not lab_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Lab not found or access denied"
        )
    
    lab = lab_data["lab"]
    progress = lab_data["user_progress"]
    stats = lab_data["statistics"]
    can_access, access_message = lab_data["can_access"]
    
    # Get category information
    category_response = None
    if lab.category:
        category_response = LabCategoryResponse.from_orm(lab.category)
    
    # Build lab detail response
    lab_detail = LabDetailResponse(
        id=lab.id,
        name=lab.name,
        slug=lab.slug,
        description=lab.description,
        short_description=lab.short_description,
        difficulty=lab.difficulty,
        estimated_time_hours=lab.estimated_time_hours,
        points=lab.points,
        status=lab.status,
        category=category_response,
        objectives=lab.objectives or [],
        prerequisites=lab.prerequisites or [],
        tags=lab.tags or [],
        vm_templates=lab.vm_templates or {},
        network_config=lab.network_config or {},
        hints_available=len(lab.hints.get("hints", [])) if lab.hints else 0,
        completion_count=lab.completion_count,
        average_completion_time_hours=lab.average_completion_time_hours,
        average_rating=lab.average_rating,
        is_featured=lab.is_featured,
        requires_subscription=lab.requires_subscription,
        created_at=lab.created_at,
        updated_at=lab.updated_at,
        published_at=lab.published_at,
        can_access=can_access,
        access_message=access_message
    )
    
    # Add user progress if available
    if progress:
        lab_detail.user_progress = LabProgressResponse(
            status=progress.status,
            completion_percentage=progress.completion_percentage,
            points_earned=progress.points_earned,
            flags_found_count=progress.flags_found_count,
            total_time_spent_hours=round(progress.total_time_spent_minutes / 60, 2),
            hints_used_count=len(progress.hints_used) if progress.hints_used else 0,
            hint_penalty_points=progress.hint_penalty_points,
            user_rating=progress.user_rating,
            first_started_at=progress.first_started_at,
            completed_at=progress.completed_at,
            last_activity_at=progress.last_activity_at
        )
    
    return lab_detail


@router.get("/category/{category_slug}", response_model=LabListResponse)
async def get_labs_by_category(
    category_slug: str,
    skip: int = Query(0, ge=0, description="Number of labs to skip"),
    limit: int = Query(50, ge=1, le=100, description="Number of labs to return"),
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Get labs in a specific category"""
    
    lab_service = LabService(db)
    
    # Get category
    category = await lab_service.get_category_by_slug(category_slug)
    if not category:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Category not found"
        )
    
    # Get labs in category
    result = await lab_service.get_labs_by_category(
        category_id=category.id,
        user=current_user,
        skip=skip,
        limit=limit
    )
    
    # Convert to response format
    lab_summaries = []
    for lab in result["labs"]:
        lab_summary = LabSummaryResponse.from_orm(lab)
        
        # Add category info
        lab_summary.category = LabCategoryResponse.from_orm(category)
        
        # Add user progress if available
        if lab.id in result["lab_progress"]:
            progress = result["lab_progress"][lab.id]
            lab_summary.user_progress = {
                "status": progress.status,
                "completion_percentage": progress.completion_percentage,
                "points_earned": progress.points_earned
            }
        
        lab_summaries.append(lab_summary)
    
    return LabListResponse(
        labs=lab_summaries,
        total=result["total"],
        page=result["page"],
        pages=result["pages"],
        has_next=result["has_next"],
        has_prev=result["has_prev"]
    )


@router.get("/search", response_model=LabListResponse)
async def search_labs(
    q: str = Query(..., min_length=2, description="Search query"),
    category: Optional[str] = Query(None, description="Filter by category slug"),
    difficulty: Optional[str] = Query(None, description="Filter by difficulty"),
    tags: Optional[str] = Query(None, description="Comma-separated tags"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Search labs with various filters"""
    
    lab_service = LabService(db)
    
    # Convert category slug to ID if provided
    category_id = None
    if category:
        category_obj = await lab_service.get_category_by_slug(category)
        if not category_obj:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Category not found"
            )
        category_id = category_obj.id
    
    # Parse tags
    tag_list = [tag.strip() for tag in tags.split(",")] if tags else None
    
    # Validate difficulty
    if difficulty and difficulty not in [d.value for d in DifficultyLevel]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid difficulty. Must be one of: {', '.join([d.value for d in DifficultyLevel])}"
        )
    
    # Search labs
    result = await lab_service.get_all_labs(
        user=current_user,
        category_id=category_id,
        difficulty=difficulty,
        search=q,
        tags=tag_list,
        skip=skip,
        limit=limit,
        include_progress=True
    )
    
    # Convert to response format
    lab_summaries = []
    for lab in result["labs"]:
        lab_summary = LabSummaryResponse.from_orm(lab)
        
        # Add user progress if available
        if lab.id in result["lab_progress"]:
            progress = result["lab_progress"][lab.id]
            lab_summary.user_progress = {
                "status": progress.status,
                "completion_percentage": progress.completion_percentage,
                "points_earned": progress.points_earned
            }
        
        lab_summaries.append(lab_summary)
    
    return LabListResponse(
        labs=lab_summaries,
        total=result["total"],
        page=result["page"],
        pages=result["pages"],
        has_next=result["has_next"],
        has_prev=result["has_prev"]
    )


@router.get("/featured", response_model=List[LabSummaryResponse])
async def get_featured_labs(
    limit: int = Query(10, ge=1, le=20, description="Number of featured labs to return"),
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Get featured/recommended labs"""
    
    lab_service = LabService(db)
    labs = await lab_service.get_featured_labs(current_user, limit)
    
    return [LabSummaryResponse.from_orm(lab) for lab in labs]


@router.get("/beginner", response_model=List[LabSummaryResponse])
async def get_beginner_labs(
    limit: int = Query(10, ge=1, le=20, description="Number of beginner labs to return"),
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Get beginner-friendly labs"""
    
    lab_service = LabService(db)
    labs = await lab_service.get_beginner_labs(current_user, limit)
    
    return [LabSummaryResponse.from_orm(lab) for lab in labs]


@router.get("/{lab_id}/statistics", response_model=LabStatisticsResponse)
async def get_lab_statistics(
    lab_id: uuid.UUID,
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Get lab statistics"""
    
    lab_service = LabService(db)
    
    # Verify user can access lab
    lab = await lab_service.get_lab_by_id(lab_id, current_user)
    if not lab:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Lab not found or access denied"
        )
    
    stats = await lab_service.get_lab_statistics(lab_id)
    return LabStatisticsResponse(**stats)


@router.get("/{lab_id}", response_model=LabDetailResponse)
async def get_lab(
    lab_id: uuid.UUID,
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Get detailed lab information by ID"""
    
    lab_service = LabService(db)
    
    # Get lab with progress and statistics
    lab_data = await lab_service.get_lab_with_progress(lab_id, current_user)
    
    if not lab_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Lab not found or access denied"
        )
    
    lab = lab_data["lab"]
    progress = lab_data["user_progress"]
    stats = lab_data["statistics"]
    can_access, access_message = lab_data["can_access"]
    
    # Get category information
    category_response = None
    if lab.category:
        category_response = LabCategoryResponse.from_orm(lab.category)
    
    # Build lab detail response
    lab_detail = LabDetailResponse(
        id=lab.id,
        name=lab.name,
        slug=lab.slug,
        description=lab.description,
        short_description=lab.short_description,
        difficulty=lab.difficulty,
        estimated_time_hours=lab.estimated_time_hours,
        points=lab.points,
        status=lab.status,
        category=category_response,
        objectives=lab.objectives or [],
        prerequisites=lab.prerequisites or [],
        tags=lab.tags or [],
        vm_templates=lab.vm_templates or {},
        network_config=lab.network_config or {},
        hints_available=len(lab.hints.get("hints", [])) if lab.hints else 0,
        completion_count=lab.completion_count,
        average_completion_time_hours=lab.average_completion_time_hours,
        average_rating=lab.average_rating,
        is_featured=lab.is_featured,
        requires_subscription=lab.requires_subscription,
        created_at=lab.created_at,
        updated_at=lab.updated_at,
        published_at=lab.published_at,
        can_access=can_access,
        access_message=access_message
    )
    
    # Add user progress if available
    if progress:
        lab_detail.user_progress = LabProgressResponse(
            status=progress.status,
            completion_percentage=progress.completion_percentage,
            points_earned=progress.points_earned,
            flags_found_count=progress.flags_found_count,
            total_time_spent_hours=round(progress.total_time_spent_minutes / 60, 2),
            hints_used_count=len(progress.hints_used) if progress.hints_used else 0,
            hint_penalty_points=progress.hint_penalty_points,
            user_rating=progress.user_rating,
            first_started_at=progress.first_started_at,
            completed_at=progress.completed_at,
            last_activity_at=progress.last_activity_at
        )
    
    return lab_detail


@router.get("/category/{category_slug}", response_model=LabListResponse)
async def get_labs_by_category(
    category_slug: str,
    skip: int = Query(0, ge=0, description="Number of labs to skip"),
    limit: int = Query(50, ge=1, le=100, description="Number of labs to return"),
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Get labs in a specific category"""
    
    lab_service = LabService(db)
    
    # Get category
    category = await lab_service.get_category_by_slug(category_slug)
    if not category:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Category not found"
        )
    
    # Get labs in category
    result = await lab_service.get_labs_by_category(
        category_id=category.id,
        user=current_user,
        skip=skip,
        limit=limit
    )
    
    # Convert to response format
    lab_summaries = []
    for lab in result["labs"]:
        lab_summary = LabSummaryResponse.from_orm(lab)
        
        # Add category info
        lab_summary.category = LabCategoryResponse.from_orm(category)
        
        # Add user progress if available
        if lab.id in result["lab_progress"]:
            progress = result["lab_progress"][lab.id]
            lab_summary.user_progress = {
                "status": progress.status,
                "completion_percentage": progress.completion_percentage,
                "points_earned": progress.points_earned
            }
        
        lab_summaries.append(lab_summary)
    
    return LabListResponse(
        labs=lab_summaries,
        total=result["total"],
        page=result["page"],
        pages=result["pages"],
        has_next=result["has_next"],
        has_prev=result["has_prev"]
    )


@router.post("/{lab_id}/start")
async def start_lab(
    lab_id: uuid.UUID,
    access_method: str = Query(..., regex="^(vpn|web)$", description="Access method: vpn or web"),
    attack_box_os: Optional[str] = Query("kali", regex="^(kali|windows)$", description="Attack box OS"),
    session_duration_hours: Optional[int] = Query(None, ge=1, le=12, description="Session duration in hours"),
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Start a lab session"""
    
    from app.services.session_service import SessionService
    from app.services.network_service import NetworkService
    from app.models.session import AccessMethod
    from app.schemas.session import SessionActionResponse
    
    lab_service = LabService(db)
    session_service = SessionService(db)
    network_service = NetworkService(db)
    
    # Verify lab exists and user can access it
    lab = await lab_service.get_lab_by_id(lab_id, current_user)
    if not lab:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Lab not found or access denied"
        )
    
    # Check access permissions
    can_access, access_message = await lab_service.can_user_access_lab(current_user, lab)
    if not can_access:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=access_message
        )
    
    # Check if Docker is available for container-based labs
    if not network_service.is_docker_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Docker service is not available. Please contact administrator."
        )
    
    try:
        # Create the session
        access_method_enum = AccessMethod.WEB if access_method == "web" else AccessMethod.VPN
        
        session = await session_service.create_session(
            user=current_user,
            lab=lab,
            access_method=access_method_enum,
            attack_box_os=attack_box_os,
            session_duration_hours=session_duration_hours
        )
        
        # Create user network
        network_success, network_result = await network_service.create_user_network(
            user_id=current_user.id,
            session_id=session.id,
            network_range=session.network_range
        )
        
        if not network_success:
            # If network creation fails, cleanup the session
            await session_service.stop_session(session.id)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to create network: {network_result}"
            )
        
        # Start the session (this will trigger VM provisioning later)
        started_session = await session_service.start_session(session.id)
        
        return {
            "success": True,
            "message": f"Lab session started successfully",
            "session_id": session.id,
            "lab_id": lab_id,
            "lab_name": lab.name,
            "status": started_session.status,
            "access_method": access_method,
            "network_range": session.network_range,
            "expires_at": session.expires_at,
            "time_remaining_minutes": session.time_remaining_minutes,
            "vm_provisioning": "In progress - VMs will be available shortly"
        }
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to start lab {lab_id} for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start lab session. Please try again."
        )


@router.post("/{lab_id}/stop")
async def stop_lab(
    lab_id: uuid.UUID,
    current_user: User = Depends(get_current_user_dependency),
    db: AsyncSession = Depends(get_db)
):
    """Stop a lab session"""
    
    # TODO: Implement lab session stopping logic
    return {
        "message": "Lab session stopping will be implemented in the next phase",
        "lab_id": lab_id,
        "status": "ready_for_implementation"
    }
