import json
import os
from typing import Any, Optional
from redis import asyncio as aioredis
from dotenv import load_dotenv

load_dotenv()

class RedisCache:
    def __init__(self, url: Optional[str] = None):
        self.url = url or os.getenv("REDIS_URL", "redis://localhost:6379")
        self.redis = None

    async def connect(self):
        if not self.redis:
            self.redis = aioredis.from_url(self.url, encoding="utf-8", decode_responses=True)

    async def close(self):
        if self.redis:
            await self.redis.aclose()
            self.redis = None

    async def get(self, key: str) -> Optional[Any]:
        await self.connect()
        data = await self.redis.get(key)
        if data:
            try:
                return json.loads(data)
            except json.JSONDecodeError:
                return data
        return None

    async def set(self, key: str, value: Any, ttl: int = 86400):
        """
        Set a key with TTL (default 24 hours).
        """
        await self.connect()
        if isinstance(value, (dict, list)):
            value = json.dumps(value)
        await self.redis.set(key, value, ex=ttl)

# Global instance
cache = RedisCache()
