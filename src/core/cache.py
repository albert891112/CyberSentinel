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
        self.url = url or os.getenv("REDIS_URL", "redis://localhost:6380")
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
        """獲取威脅類型對應的 Redis ZSET key"""
        return f"webrisk:{threat_type.lower()}:zset"

    def _get_threat_state_key(self, threat_type: str) -> str:
        """獲取威脅類型狀態 (version_token) 的 Redis key"""
        return f"webrisk:metadata:{threat_type.lower()}"

    async def add_hash_prefixes(self, threat_type: str, prefixes: List[int]) -> int:
        """
        批量新增 hash prefixes 到對應的威脅類型 ZSET 中。
        使用 hash 值同時作為 member 和 score，維護排序。
        
        Args:
            threat_type: 威脅類型 (如 "MALWARE", "SOCIAL_ENGINEERING")
            prefixes: hash prefix 列表 (整數)
            
        Returns:
            新增的數量
        """
        if not prefixes:
            return 0
        await self.connect_binary()
        key = self._get_threat_list_key(threat_type)
        # 使用 ZADD 批量新增，score = member = hash 值
        # mapping: {member: score}
        mapping = {str(p): p for p in prefixes}
        return await self._binary_redis.zadd(key, mapping)

    async def remove_hash_prefixes(self, threat_type: str, prefixes: List[int]) -> int:
        """
        批量移除 hash prefixes。
        
        Args:
            threat_type: 威脅類型
            prefixes: 要移除的 hash prefix 列表 (整數)
            
        Returns:
            移除的數量
        """
        if not prefixes:
            return 0
        await self.connect_binary()
        key = self._get_threat_list_key(threat_type)
        # 轉為字串成員進行 ZREM
        members = [str(p) for p in prefixes]
        return await self._binary_redis.zrem(key, *members)

    async def remove_by_indices(self, threat_type: str, indices: List[int]) -> int:
        """
        依據索引位置刪除 ZSET 中的資料（使用 Lua Script 原子操作）。
        關鍵：索引必須由大到小排序，以避免刪除時索引錯位。
        
        Args:
            threat_type: 威脅類型
            indices: 要刪除的索引列表
            
        Returns:
            實際移除的數量
        """
        if not indices:
            return 0
        await self.connect_binary()
        key = self._get_threat_list_key(threat_type)
        
        # 在 Python 端先排序，比在 Lua 排更省 Redis CPU
        sorted_indices = sorted(indices, reverse=True)
        
        # Lua Script: 傳入 Key 和排好序的 Indices
        # Redis ZRANGE 是 0-based，直接傳入 Python 的 0-based index
        lua_script = """
        local key = KEYS[1]
        local indices = cjson.decode(ARGV[1])
        local removed_count = 0
        
        for i, idx in ipairs(indices) do
            -- ZRANGE key start stop (取 1 個)
            local members = redis.call('ZRANGE', key, idx, idx)
            if #members > 0 then
                redis.call('ZREM', key, members[1])
                removed_count = removed_count + 1
            end
        end
        return removed_count
        """
        
        # 註冊並執行 Script
        script = self._binary_redis.register_script(lua_script)
        
        # 將 indices 轉為 JSON 字串傳入 (Redis Lua 接收 ARGV 都是字串)
        import json
        return await script(keys=[key], args=[json.dumps(sorted_indices)])

    async def check_hash_prefix(self, prefix: int) -> List[str]:
        """
        檢查 hash prefix 是否存在於任何威脅清單 ZSET 中。
        使用 ZSCORE 檢查成員是否存在。
        
        Args:
            prefix: 要檢查的 hash prefix (整數)
            
        Returns:
            匹配的威脅類型列表
        """
        await self.connect_binary()
        matched_types = []
        member = str(prefix)
        for threat_type in WEBRISK_THREAT_TYPES:
            key = self._get_threat_list_key(threat_type)
            score = await self._binary_redis.zscore(key, member)
            if score is not None:
                matched_types.append(threat_type)
        return matched_types

    async def check_hash_prefixes_batch(self, prefixes: List[int]) -> dict:
        """
        批量檢查多個 hash prefixes（使用 ZSET ZSCORE）。
        
        Args:
            prefixes: hash prefix 列表 (整數)
            
        Returns:
            Dict[int, List[str]] - prefix 對應的威脅類型列表
        """
        await self.connect_binary()
        results = {}
        pipe = self._binary_redis.pipeline()
        
        # 為每個 prefix 和威脅類型建立查詢
        queries = []
        for prefix in prefixes:
            member = str(prefix)
            for threat_type in WEBRISK_THREAT_TYPES:
                key = self._get_threat_list_key(threat_type)
                pipe.zscore(key, member)
                queries.append((prefix, threat_type))
        
        # 執行批量查詢
        responses = await pipe.execute()
        
        # 解析結果 (ZSCORE 返回 None 表示不存在)
        for (prefix, threat_type), score in zip(queries, responses):
            if score is not None:
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

    async def delete_threat_list_state(self, threat_type: str):
        """
        刪除威脅清單的同步狀態 (version_token)。
        在 RESET 時使用，強迫下次進行全量更新。
        
        Args:
            threat_type: 威脅類型
        """
        await self.connect_binary()
        key = self._get_threat_state_key(threat_type)
        await self._binary_redis.delete(key)

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
        return await self._binary_redis.zcard(key)

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
