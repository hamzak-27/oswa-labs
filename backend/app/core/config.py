"""
Configuration settings for CyberLab Platform
"""

from pydantic_settings import BaseSettings
from typing import List, Optional
import secrets


class Settings(BaseSettings):
    """Application settings"""
    
    # Application
    PROJECT_NAME: str = "CyberLab Platform"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    
    # Security
    SECRET_KEY: str = secrets.token_urlsafe(32)
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Database
    DATABASE_URL: str = "postgresql+asyncpg://cyberlab_user:cyberlab_dev_password@localhost:5432/cyberlab"
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:3001", 
        "http://127.0.0.1:3000"
    ]
    ALLOWED_HOSTS: List[str] = ["localhost", "127.0.0.1"]
    
    # Guacamole Integration
    GUACAMOLE_URL: str = "http://localhost:8080/guacamole"
    GUACAMOLE_USERNAME: str = "guacadmin"
    GUACAMOLE_PASSWORD: str = "guacadmin"
    
    # Proxmox Configuration
    PROXMOX_HOST: Optional[str] = None
    PROXMOX_USER: Optional[str] = None
    PROXMOX_PASSWORD: Optional[str] = None
    PROXMOX_NODE: Optional[str] = None
    PROXMOX_VERIFY_SSL: bool = False
    
    # VPN Configuration
    OPENVPN_SERVER_IP: Optional[str] = None
    OPENVPN_PORT: int = 1194
    OPENVPN_PROTOCOL: str = "udp"
    OPENVPN_DATA_PATH: str = "C:\\Users\\ihamz\\htb-1\\cyberlab-platform\\docker\\vpn\\openvpn-data"
    OPENVPN_CA_CERT_PATH: str = "/etc/openvpn/ca.crt"
    OPENVPN_SERVER_CERT_PATH: str = "/etc/openvpn/server.crt"
    OPENVPN_SERVER_KEY_PATH: str = "/etc/openvpn/server.key"
    
    # Network Configuration
    USER_NETWORK_BASE: str = "10.10.0.0/16"
    USER_NETWORK_MASK: int = 24
    VPN_NETWORK_BASE: str = "10.8.0.0/16"
    
    # Lab Session Configuration
    DEFAULT_SESSION_DURATION_HOURS: int = 4
    MAX_CONCURRENT_SESSIONS_PER_USER: int = 2
    VM_STARTUP_TIMEOUT_MINUTES: int = 10
    AUTO_CLEANUP_IDLE_SESSIONS_HOURS: int = 6
    
    # File Storage (MinIO)
    MINIO_ENDPOINT: str = "localhost:9000"
    MINIO_ACCESS_KEY: str = "minioadmin"
    MINIO_SECRET_KEY: str = "minioadmin123"
    MINIO_BUCKET_NAME: str = "cyberlab-files"
    MINIO_SECURE: bool = False
    
    # Monitoring
    INFLUXDB_URL: str = "http://localhost:8086"
    INFLUXDB_TOKEN: Optional[str] = None
    INFLUXDB_ORG: str = "cyberlab"
    INFLUXDB_BUCKET: str = "metrics"
    
    # Email Configuration
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_TLS: bool = True
    SMTP_SSL: bool = False
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_BURST: int = 100
    
    # Logging
    LOG_LEVEL: str = "INFO"
    
    class Config:
        env_file = ".env"
        case_sensitive = True


# Create settings instance
settings = Settings()


# Derived settings
def get_database_url() -> str:
    """Get database URL for SQLAlchemy"""
    return settings.DATABASE_URL


def get_redis_url() -> str:
    """Get Redis URL"""
    return settings.REDIS_URL


def is_development() -> bool:
    """Check if running in development mode"""
    return settings.ENVIRONMENT == "development"


def is_production() -> bool:
    """Check if running in production mode"""
    return settings.ENVIRONMENT == "production"
