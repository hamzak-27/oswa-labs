"""
CyberLab Platform - Main FastAPI Application
"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer
from contextlib import asynccontextmanager
import uvicorn
from loguru import logger

from app.core.config import settings
from app.core.database import engine
from app.core.redis import redis_client
from app.api.v1.router import api_router
from app.models import Base


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    logger.info("Starting CyberLab Platform...")
    
    # Create database tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # Test Redis connection
    try:
        await redis_client.ping()
        logger.info("Redis connection established")
    except Exception as e:
        logger.error(f"Redis connection failed: {e}")
    
    logger.info("Application startup complete")
    
    yield
    
    # Shutdown
    logger.info("Shutting down CyberLab Platform...")
    await redis_client.close()
    await engine.dispose()


# Create FastAPI application
app = FastAPI(
    title="CyberLab Platform API",
    description="Backend API for cybersecurity lab management platform",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan
)

# Add security middleware
security = HTTPBearer()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["*"],
)

# Add trusted host middleware for production
if settings.ENVIRONMENT == "production":
    app.add_middleware(
        TrustedHostMiddleware, 
        allowed_hosts=settings.ALLOWED_HOSTS
    )

# Include API routes
app.include_router(api_router, prefix="/api/v1")


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "CyberLab Platform API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/api/docs"
    }


@app.post("/test/start_lab")
async def test_start_lab():
    """Test endpoint to start a lab without authentication (for testing only)"""
    try:
        from app.services.vm_service import VMService
        from app.core.database import get_db
        import uuid
        
        # Create a mock session for testing
        mock_session_id = uuid.uuid4()
        
        # Get database session
        async for db in get_db():
            vm_service = VMService(db)
            
            # Try to provision lab environment
            success, message = await vm_service.provision_lab_environment(mock_session_id)
            
            return {
                "success": success,
                "message": message,
                "session_id": str(mock_session_id),
                "note": "This is a test endpoint - check 'docker ps' to see containers"
            }
            
    except Exception as e:
        logger.error(f"Test lab start failed: {e}")
        raise HTTPException(status_code=500, detail=f"Test failed: {str(e)}")


@app.get("/health")
async def health_check():
    """Health check endpoint for load balancers"""
    try:
        # Check database connection
        from sqlalchemy import text
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
        
        # Check Redis connection
        await redis_client.ping()
        
        return {
            "status": "healthy",
            "database": "connected",
            "redis": "connected"
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unhealthy")


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level="info" if not settings.DEBUG else "debug"
    )
