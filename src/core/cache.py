import json
import os
from typing import Any, Optional, List
from redis import asyncio as aioredis
from dotenv import load_dotenv

load_dotenv()

# Web Risk 威脅類型常數
WEBRISK_THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]


class RedisCache:
    def __init__(self, url: Optional[str] = None):
        self.url = url or os.getenv("REDIS_URL", "redis://localhost:6379")
        self.redis = None
        self._binary_redis = None  # 用於處理二進位資料的連線

    async def connect(self):
        if not self.redis:
            self.redis = aioredis.from_url(self.url, encoding="utf-8", decode_responses=True)

    async def connect_binary(self):
        """連接 Redis（不解碼回應，用於二進位資料）"""
        if not self._binary_redis:
            self._binary_redis = aioredis.from_url(self.url, decode_responses=False)

    async def close(self):
        if self.redis:
            await self.redis.aclose()
            self.redis = None
        if self._binary_redis:
            await self._binary_redis.aclose()
            self._binary_redis = None

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

    # =============================================
    # Web Risk 威脅清單緩存相關方法
    # =============================================

    def _get_threat_list_key(self, threat_type: str) -> str:
        """獲取威脅類型對應的 Redis Set key"""
        return f"webrisk:threatlist:{threat_type}"

    def _get_threat_state_key(self, threat_type: str) -> str:
        """獲取威脅類型狀態的 Redis key"""
        return f"webrisk:state:{threat_type}"

    async def add_hash_prefixes(self, threat_type: str, prefixes: List[bytes]) -> int:
        """
        批量新增 hash prefixes 到對應的威脅類型集合中。
        
        Args:
            threat_type: 威脅類型 (如 "MALWARE", "SOCIAL_ENGINEERING")
            prefixes: hash prefix 列表 (bytes)
            
        Returns:
            新增的數量
        """
        if not prefixes:
            return 0
        await self.connect_binary()
        key = self._get_threat_list_key(threat_type)
        # 使用 SADD 批量新增
        return await self._binary_redis.sadd(key, *prefixes)

    async def remove_hash_prefixes(self, threat_type: str, prefixes: List[bytes]) -> int:
        """
        批量移除 hash prefixes。
        
        Args:
            threat_type: 威脅類型
            prefixes: 要移除的 hash prefix 列表
            
        Returns:
            移除的數量
        """
        if not prefixes:
            return 0
        await self.connect_binary()
        key = self._get_threat_list_key(threat_type)
        return await self._binary_redis.srem(key, *prefixes)

    async def check_hash_prefix(self, prefix: bytes) -> List[str]:
        """
        檢查 hash prefix 是否存在於任何威脅清單中。
        
        Args:
            prefix: 要檢查的 hash prefix (bytes)
            
        Returns:
            匹配的威脅類型列表
        """
        await self.connect_binary()
        matched_types = []
        for threat_type in WEBRISK_THREAT_TYPES:
            key = self._get_threat_list_key(threat_type)
            if await self._binary_redis.sismember(key, prefix):
                matched_types.append(threat_type)
        return matched_types

    async def check_hash_prefixes_batch(self, prefixes: List[bytes]) -> dict:
        """
        批量檢查多個 hash prefixes。
        
        Args:
            prefixes: hash prefix 列表
            
        Returns:
            Dict[bytes, List[str]] - prefix 對應的威脅類型列表
        """
        await self.connect_binary()
        results = {}
        pipe = self._binary_redis.pipeline()
        
        # 為每個 prefix 和威脅類型建立查詢
        queries = []
        for prefix in prefixes:
            for threat_type in WEBRISK_THREAT_TYPES:
                key = self._get_threat_list_key(threat_type)
                pipe.sismember(key, prefix)
                queries.append((prefix, threat_type))
        
        # 執行批量查詢
        responses = await pipe.execute()
        
        # 解析結果
        for (prefix, threat_type), is_member in zip(queries, responses):
            if is_member:
                if prefix not in results:
                    results[prefix] = []
                results[prefix].append(threat_type)
        
        return results

    async def get_threat_list_state(self, threat_type: str) -> Optional[bytes]:
        """
        獲取威脅清單的同步狀態 (用於 compute_diff 的 version_token)。
        
        Args:
            threat_type: 威脅類型
            
        Returns:
            state token (bytes) 或 None
        """
        await self.connect_binary()
        key = self._get_threat_state_key(threat_type)
        return await self._binary_redis.get(key)

    async def set_threat_list_state(self, threat_type: str, state: bytes):
        """
        設定威脅清單的同步狀態。
        
        Args:
            threat_type: 威脅類型
            state: 新的 state token
        """
        await self.connect_binary()
        key = self._get_threat_state_key(threat_type)
        await self._binary_redis.set(key, state)

    async def get_threat_list_size(self, threat_type: str) -> int:
        """
        獲取威脅清單中的 hash prefix 數量。
        
        Args:
            threat_type: 威脅類型
            
        Returns:
            hash prefix 數量
        """
        await self.connect_binary()
        key = self._get_threat_list_key(threat_type)
        return await self._binary_redis.scard(key)

    async def clear_threat_list(self, threat_type: str):
        """
        清空威脅清單（在需要完整重置時使用）。
        
        Args:
            threat_type: 威脅類型
        """
        await self.connect_binary()
        key = self._get_threat_list_key(threat_type)
        await self._binary_redis.delete(key)


# Global instance
cache = RedisCache()
