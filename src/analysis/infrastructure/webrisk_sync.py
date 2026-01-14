"""
Web Risk 威脅清單同步服務

此模組負責定期從 Google Web Risk API 同步威脅清單到本地 Redis 緩存。
使用 compute_diff API 進行增量更新，最小化網路傳輸和處理時間。

使用方式:
    # 作為背景任務運行
    python -m src.analysis.infrastructure.webrisk_sync
    
    # 或在應用程式中導入並啟動
    from src.analysis.infrastructure.webrisk_sync import start_sync_worker
    asyncio.create_task(start_sync_worker())

環境變數:
    GOOGLE_APPLICATION_CREDENTIALS: 服務帳戶密鑰檔案路徑
    REDIS_URL: Redis 連接 URL (預設: redis://localhost:6379)
    WEBRISK_SYNC_INTERVAL: 同步間隔秒數 (預設: 1800，即 30 分鐘)
"""

import asyncio
import os
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from google.cloud import webrisk_v1
from google.cloud.webrisk_v1.services.web_risk_service import WebRiskServiceClient
from src.core.cache import cache, WEBRISK_THREAT_TYPES

# 設定日誌
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# =============================================
# Rice-Golomb 解碼器
# =============================================

class BitReader:
    """位元讀取器，用於處理 Rice-Golomb 編碼的二進位資料"""
    
    def __init__(self, data: bytes):
        self.data = data
        self.byte_idx = 0
        self.bit_idx = 0  # 0-7, current bit in byte
        self.data_len = len(data)

    def read_bits(self, num_bits: int) -> int:
        """讀取指定數量的 bits 並返回整數"""
        result = 0
        for _ in range(num_bits):
            if self.byte_idx >= self.data_len:
                raise EOFError("End of stream reached")
            
            # 從 MSB 讀到 LSB (Google Web Risk 規範)
            current_byte = self.data[self.byte_idx]
            bit = (current_byte >> (7 - self.bit_idx)) & 1
            
            result = (result << 1) | bit
            
            self.bit_idx += 1
            if self.bit_idx == 8:
                self.bit_idx = 0
                self.byte_idx += 1
        return result

    def read_unary(self) -> int:
        """讀取 Unary 編碼 (計算連續的 0，直到遇到 1)"""
        count = 0
        while True:
            bit = self.read_bits(1)
            if bit == 1:
                break
            count += 1
        return count


def decode_rice_golomb(
    encoded_data: bytes,
    first_value: int,
    rice_parameter: int,
    entry_count: int
) -> list[int]:
    """
    解碼 Rice-Golomb 壓縮資料。
    
    Args:
        encoded_data: API 回傳的壓縮 bytes
        first_value: rice_hashes.first_value
        rice_parameter: rice_hashes.rice_parameter (k)
        entry_count: rice_hashes.entry_count
        
    Returns:
        解碼後的 hash prefix 整數列表
    """
    hashes = []
    
    # 第一個值直接加入
    current_hash = first_value
    hashes.append(current_hash)
    
    reader = BitReader(encoded_data)
    
    # 解碼剩餘的 entry_count - 1 個值
    for _ in range(entry_count - 1):
        try:
            # Quotient (Unary coding)
            q = reader.read_unary()
            
            # Remainder (Binary coding, k bits)
            r = reader.read_bits(rice_parameter)
            
            # Delta = q * (2^k) + r
            delta = (q << rice_parameter) + r
            
            # 累加
            current_hash += delta
            hashes.append(current_hash)
            
        except EOFError:
            break
            
    return hashes

class WebRiskSyncService:
    """
    Web Risk 威脅清單同步服務。
    
    負責定期從 Google Web Risk API 拉取威脅清單更新，
    並將 hash prefixes 存儲到 Redis 中。
    """
    
    def __init__(self):
        self._client: Optional[WebRiskServiceClient] = None
        self._sync_interval = int(os.getenv("WEBRISK_SYNC_INTERVAL", "1800"))
        self._running = False
        
    @property
    def client(self):
        """懶加載 Web Risk 客戶端"""
        if self._client is None:
            try:
                self._client = WebRiskServiceClient()
            except Exception as e:
                logger.error(f"Failed to initialize Web Risk client: {e}")
                return None
        return self._client
    
    def _threat_type_to_enum(self, threat_type_name: str):
        """將威脅類型名稱轉換為 API 枚舉值"""
        return getattr(webrisk_v1.ThreatType, threat_type_name, None)
    
    async def sync_threat_list(self, threat_type: str) -> Dict[str, Any]:
        """
        同步單一威脅類型的清單。
        
        使用 compute_diff API 進行增量更新：
        - 如果有 version_token，發送增量請求
        - 如果沒有或版本失效，進行完整同步
        
        Args:
            threat_type: 威脅類型名稱 (如 "MALWARE")
            
        Returns:
            Dict 包含同步結果
        """
        client = self.client
        if client is None:
            return {"error": "Web Risk client unavailable"}
        
        try:
            # 獲取當前版本狀態
            version_token = await cache.get_threat_list_state(threat_type)
             
            # 轉換威脅類型
            threat_enum = self._threat_type_to_enum(threat_type)
            if threat_enum is None:
                return {"error": f"Unknown threat type: {threat_type}"}
            
            # 準備請求
            loop = asyncio.get_event_loop()
            
            def _compute_diff():
                constraints = webrisk_v1.ComputeThreatListDiffRequest.Constraints(
                    max_diff_entries=10000,  # 每次最多處理的條目數
                    max_database_entries=500000,  # 本地資料庫最大條目數
                    supported_compressions=[
                        webrisk_v1.CompressionType.RICE,
                    ]
                )
                
                request = webrisk_v1.ComputeThreatListDiffRequest(
                    threat_type=threat_enum,
                    version_token=version_token if version_token else b"",
                    constraints=constraints,
                )
                
                return client.compute_threat_list_diff(request=request)
            
            response = await loop.run_in_executor(None, _compute_diff)
            
            # 處理回應
            stats = {
                "threat_type": threat_type,
                "response_type": response.response_type.name,
                "additions": 0,
                "removals": 0,
            }
            
            # 步驟 8：處理 RESET - 清空資料並刪除 token
            if response.response_type == webrisk_v1.ComputeThreatListDiffResponse.ResponseType.RESET:
                logger.info(f"Performing full reset for {threat_type}")
                await cache.clear_threat_list(threat_type)
                # 清除 version token，強迫下次進行全量更新
                await cache.delete_threat_list_state(threat_type)
            
            # 步驟 6：先處理移除 (BEFORE additions!)
            # 關鍵：必須在新增之前處理移除，且索引由大到小排序
            if response.removals:
                removal_indices = []
                
                # 處理原始索引格式
                if response.removals.raw_indices:
                    removal_indices = list(response.removals.raw_indices.indices)
                
                # 處理 Rice 壓縮的索引
                if response.removals.rice_indices:
                    rice_idx = response.removals.rice_indices
                    decoded_indices = decode_rice_golomb(
                        rice_idx.encoded_data,
                        rice_idx.first_value,
                        rice_idx.rice_parameter,
                        rice_idx.entry_count
                    )
                    removal_indices.extend(decoded_indices)
                
                if removal_indices:
                    # 使用新的 remove_by_indices 方法 (內部會由大到小排序)
                    removed = await cache.remove_by_indices(threat_type, removal_indices)
                    stats["removals"] = removed
                    logger.info(f"Removed {removed} prefixes for {threat_type} (from {len(removal_indices)} indices)")
            
            # 步驟 7：處理新增項目
            if response.additions:
                prefixes_to_add = []
                
                # 處理原始資料格式
                if response.additions.raw_hashes:
                    for raw_hash_entry in response.additions.raw_hashes:
                        raw_data = raw_hash_entry.raw_hashes
                        prefix_size = raw_hash_entry.prefix_size
                        
                        # 將原始 bytes 轉為整數 (用於 ZSET)
                        for i in range(0, len(raw_data), prefix_size):
                            prefix_bytes = raw_data[i:i + prefix_size]
                            if len(prefix_bytes) == prefix_size:
                                # 轉為整數
                                prefix_int = int.from_bytes(prefix_bytes, byteorder='big')
                                prefixes_to_add.append(prefix_int)
                
                # 處理 Rice-Golomb 壓縮格式
                if response.additions.rice_hashes:
                    rice_hashes = response.additions.rice_hashes
                    decoded_hashes = decode_rice_golomb(
                        rice_hashes.encoded_data,
                        rice_hashes.first_value,
                        rice_hashes.rice_parameter,
                        rice_hashes.entry_count
                    )
                    prefixes_to_add.extend(decoded_hashes)
                
                if prefixes_to_add:
                    added = await cache.add_hash_prefixes(threat_type, prefixes_to_add)
                    stats["additions"] = added
                    logger.info(f"Added {added} prefixes for {threat_type}")
            
            # 步驟 8：保存新的 version token
            if response.new_version_token:
                await cache.set_threat_list_state(threat_type, response.new_version_token)
            
            # 記錄推薦的下次同步時間
            if response.recommended_next_diff:
                # recommended_next_diff 是 Timestamp，轉換為秒數計算
                next_diff_time = response.recommended_next_diff
                now = datetime.now(timezone.utc)
                # 使用 timestamp() 方法獲取 POSIX timestamp 進行計算
                next_diff_seconds = int(next_diff_time.timestamp() - now.timestamp())
                stats["recommended_next_diff_seconds"] = max(0, next_diff_seconds)
                logger.info(f"Recommended next diff for {threat_type}: {next_diff_seconds}s")
            
            # 獲取當前清單大小
            list_size = await cache.get_threat_list_size(threat_type)
            stats["total_entries"] = list_size
            
            return stats
            
        except Exception as e:
            logger.error(f"Error syncing {threat_type}: {e}")
            return {"error": str(e), "threat_type": threat_type}
    
    async def sync_all_threat_lists(self) -> Dict[str, Any]:
        """
        同步所有威脅類型的清單。
        
        Returns:
            Dict 包含各威脅類型的同步結果
        """
        results = {}
        for threat_type in WEBRISK_THREAT_TYPES:
            logger.info(f"Syncing threat list: {threat_type}")
            results[threat_type] = await self.sync_threat_list(threat_type)
        return results
    
    async def start_sync_worker(self):
        """
        啟動定期同步工作者。
        
        這是一個無限迴圈，定期同步威脅清單。
        適合作為背景任務運行。
        """
        self._running = True
        logger.info(f"Starting Web Risk sync worker (interval: {self._sync_interval}s)")
        
        while self._running:
            try:
                start_time = datetime.now(timezone.utc)
                logger.info(f"Starting sync at {start_time.isoformat()}")
                
                results = await self.sync_all_threat_lists()
                
                end_time = datetime.now(timezone.utc)
                duration = (end_time - start_time).total_seconds()
                logger.info(f"Sync completed in {duration:.2f}s: {results}")
                
            except Exception as e:
                logger.error(f"Sync worker error: {e}")
            
            # 等待下一次同步
            await asyncio.sleep(self._sync_interval)
    
    def stop_sync_worker(self):
        """停止同步工作者"""
        self._running = False
        logger.info("Sync worker stopped")


# 全域實例
sync_service = WebRiskSyncService()


async def start_sync_worker():
    """啟動同步工作者的便捷函數"""
    await sync_service.start_sync_worker()


async def sync_once():
    """執行一次性同步的便捷函數"""
    return await sync_service.sync_all_threat_lists()


# 作為獨立腳本運行
if __name__ == "__main__":
    asyncio.run(start_sync_worker())
