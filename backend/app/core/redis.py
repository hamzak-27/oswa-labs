"""
Redis connection and utilities
"""

import redis.asyncio as redis
from typing import Optional, Any
import json
from app.core.config import settings
from loguru import logger


class RedisClient:
    """Redis client wrapper"""
    
    def __init__(self):
        self.redis: Optional[redis.Redis] = None
    
    async def connect(self):
        """Connect to Redis"""
        try:
            self.redis = redis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True
            )
            await self.redis.ping()
            logger.info("Redis connection established")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise
    
    async def close(self):
        """Close Redis connection"""
        if self.redis:
            await self.redis.close()
    
    async def ping(self) -> bool:
        """Test Redis connection"""
        if not self.redis:
            await self.connect()
        return await self.redis.ping()
    
    async def set(self, key: str, value: Any, expire: Optional[int] = None) -> bool:
        """Set a key-value pair"""
        if not self.redis:
            await self.connect()
        
        if isinstance(value, (dict, list)):
            value = json.dumps(value)
        
        return await self.redis.set(key, value, ex=expire)
    
    async def get(self, key: str) -> Optional[str]:
        """Get value by key"""
        if not self.redis:
            await self.connect()
        
        return await self.redis.get(key)
    
    async def get_json(self, key: str) -> Optional[Any]:
        """Get and parse JSON value"""
        value = await self.get(key)
        if value:
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return value
        return None
    
    async def delete(self, key: str) -> int:
        """Delete a key"""
        if not self.redis:
            await self.connect()
        
        return await self.redis.delete(key)
    
    async def exists(self, key: str) -> bool:
        """Check if key exists"""
        if not self.redis:
            await self.connect()
        
        return bool(await self.redis.exists(key))
    
    async def expire(self, key: str, seconds: int) -> bool:
        """Set expiration for a key"""
        if not self.redis:
            await self.connect()
        
        return await self.redis.expire(key, seconds)
    
    async def get_all_keys(self, pattern: str = "*") -> list:
        """Get all keys matching pattern"""
        if not self.redis:
            await self.connect()
        
        return await self.redis.keys(pattern)
    
    async def increment(self, key: str, amount: int = 1) -> int:
        """Increment a counter"""
        if not self.redis:
            await self.connect()
        
        return await self.redis.incr(key, amount)
    
    async def set_hash(self, name: str, mapping: dict, expire: Optional[int] = None) -> bool:
        """Set hash fields"""
        if not self.redis:
            await self.connect()
        
        result = await self.redis.hset(name, mapping=mapping)
        if expire:
            await self.redis.expire(name, expire)
        return bool(result)
    
    async def get_hash(self, name: str, key: str) -> Optional[str]:
        """Get hash field value"""
        if not self.redis:
            await self.connect()
        
        return await self.redis.hget(name, key)
    
    async def get_all_hash(self, name: str) -> dict:
        """Get all hash fields"""
        if not self.redis:
            await self.connect()
        
        return await self.redis.hgetall(name)


# Create global Redis client instance
redis_client = RedisClient()


# Cache decorators and utilities
class CacheKeys:
    """Redis cache key patterns"""
    
    USER_SESSION = "user_session:{user_id}"
    LAB_SESSION = "lab_session:{session_id}"
    VM_STATUS = "vm_status:{vm_id}"
    USER_PROGRESS = "user_progress:{user_id}:{lab_id}"
    ACTIVE_SESSIONS = "active_sessions:{user_id}"
    NETWORK_ALLOCATION = "network_allocation"
    RATE_LIMIT = "rate_limit:{user_id}:{endpoint}"


async def cache_user_session(user_id: str, session_data: dict, expire_seconds: int = 3600):
    """Cache user session data"""
    key = CacheKeys.USER_SESSION.format(user_id=user_id)
    await redis_client.set(key, session_data, expire=expire_seconds)


async def get_cached_user_session(user_id: str) -> Optional[dict]:
    """Get cached user session data"""
    key = CacheKeys.USER_SESSION.format(user_id=user_id)
    return await redis_client.get_json(key)


async def cache_lab_session(session_id: str, session_data: dict, expire_seconds: int = 14400):
    """Cache lab session data (4 hours default)"""
    key = CacheKeys.LAB_SESSION.format(session_id=session_id)
    await redis_client.set(key, session_data, expire=expire_seconds)


async def get_cached_lab_session(session_id: str) -> Optional[dict]:
    """Get cached lab session data"""
    key = CacheKeys.LAB_SESSION.format(session_id=session_id)
    return await redis_client.get_json(key)
