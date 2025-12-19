import redis.asyncio as redis
import json
import hashlib
from app.config import settings

class AnalysisCache:
    def __init__(self):
        self.redis = redis.from_url(settings.REDIS_URL)
        self.ttl = 86400 # 24 hours

    def _get_key(self, url: str) -> str:
        url_hash = hashlib.md5(url.encode()).hexdigest()
        return f"analysis:{url_hash}"

    async def get_result(self, url: str) -> dict | None:
        key = self._get_key(url)
        data = await self.redis.get(key)
        if data:
            return json.loads(data)
        return None

    async def set_result(self, url: str, result: dict):
        key = self._get_key(url)
        await self.redis.set(key, json.dumps(result), ex=self.ttl)
