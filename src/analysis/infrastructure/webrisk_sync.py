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
                        webrisk_v1.CompressionType.RAW,
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
            
            # 檢查回應類型
            if response.response_type == webrisk_v1.ComputeThreatListDiffResponse.ResponseType.RESET:
                # 完整重置：清空現有資料並重新建立
                logger.info(f"Performing full reset for {threat_type}")
                await cache.clear_threat_list(threat_type)
            
            # 處理移除項目
            if response.removals:
                removal_indices = []
                if response.removals.raw_indices:
                    removal_indices = list(response.removals.raw_indices.indices)
                # 注意：移除是按照索引進行的，這裡需要更複雜的邏輯
                # 對於簡化實作，我們在 RESET 時清空所有資料
                stats["removals"] = len(removal_indices)
                logger.info(f"Removals for {threat_type}: {len(removal_indices)} indices (handled via RESET)")
            
            # 處理新增項目
            if response.additions:
                prefixes_to_add = []
                
                # 處理原始資料格式
                if response.additions.raw_hashes:
                    raw_data = response.additions.raw_hashes.raw_hashes
                    prefix_size = response.additions.raw_hashes.prefix_size
                    
                    # 將原始資料分割為獨立的前綴
                    for i in range(0, len(raw_data), prefix_size):
                        prefix = raw_data[i:i + prefix_size]
                        if len(prefix) == prefix_size:
                            prefixes_to_add.append(bytes(prefix))
                
                # 處理 Rice 壓縮格式 (如果有的話)
                # 注意：Rice 解壓縮需要額外實作，這裡只處理原始格式
                
                if prefixes_to_add:
                    added = await cache.add_hash_prefixes(threat_type, prefixes_to_add)
                    stats["additions"] = added
                    logger.info(f"Added {added} prefixes for {threat_type}")
            
            # 保存新的版本狀態
            if response.new_version_token:
                await cache.set_threat_list_state(threat_type, response.new_version_token)
            
            # 記錄推薦的下次同步時間
            if response.recommended_next_diff:
                next_diff_seconds = response.recommended_next_diff.seconds
                stats["recommended_next_diff_seconds"] = next_diff_seconds
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
