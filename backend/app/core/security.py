"""
Security utilities for authentication and authorization
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from passlib.context import CryptContext
from app.core.config import settings

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Generate password hash"""
    return pwd_context.hash(password)


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire, "type": "access"})
    
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: Dict[str, Any]) -> str:
    """Create JWT refresh token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    
    to_encode.update({"exp": expire, "type": "refresh"})
    
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def verify_token(token: str) -> Dict[str, Any]:
    """Verify and decode JWT token"""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except JWTError as e:
        raise ValueError(f"Invalid token: {e}")


def decode_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode JWT token without verification (for debugging)"""
    try:
        return jwt.get_unverified_claims(token)
    except Exception:
        return None


def is_token_expired(token: str) -> bool:
    """Check if token is expired"""
    try:
        payload = jwt.get_unverified_claims(token)
        exp = payload.get("exp")
        if exp:
            return datetime.utcnow() > datetime.fromtimestamp(exp)
        return True
    except Exception:
        return True


def generate_secure_key(length: int = 32) -> str:
    """Generate a secure random key"""
    import secrets
    return secrets.token_urlsafe(length)


def generate_session_id() -> str:
    """Generate unique session ID"""
    import secrets
    return secrets.token_hex(16)


def hash_sensitive_data(data: str) -> str:
    """Hash sensitive data for storage"""
    import hashlib
    return hashlib.sha256(data.encode()).hexdigest()


def validate_password_strength(password: str) -> tuple[bool, str]:
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"
    
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if not any(c in special_chars for c in password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is strong"


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe storage"""
    import re
    # Remove or replace dangerous characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Limit length
    if len(filename) > 255:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        filename = name[:250] + ('.' + ext if ext else '')
    return filename


def generate_lab_network_range(user_index: int) -> str:
    """Generate unique network range for user lab"""
    # Generate network like 10.10.{user_index}.0/24
    if user_index > 65535:  # Max for /16 network
        raise ValueError("User index too high for network allocation")
    
    return f"10.10.{user_index}.0/24"


def generate_vpn_client_config(
    user_id: str, 
    user_index: int,
    server_ip: str,
    ca_cert: str,
    client_cert: str,
    client_key: str
) -> str:
    """Generate OpenVPN client configuration"""
    
    config = f"""# CyberLab Platform - OpenVPN Configuration
# User: {user_id}
# Generated: {datetime.utcnow().isoformat()}

client
dev tun
proto {settings.OPENVPN_PROTOCOL}
remote {server_ip} {settings.OPENVPN_PORT}
resolv-retry infinite
nobind
persist-key
persist-tun

# Security
cipher AES-256-GCM
auth SHA256
key-direction 1
remote-cert-tls server

# Compression
compress lz4-v2
push "compress lz4-v2"

# Logging
verb 3

# Routes for lab network
route 10.10.{user_index}.0 255.255.255.0

<ca>
{ca_cert}
</ca>

<cert>
{client_cert}
</cert>

<key>
{client_key}
</key>
"""
    return config
