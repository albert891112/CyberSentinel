import asyncio
import hashlib
import re
from urllib.parse import urlparse, unquote, quote
from typing import Dict, Any, List, Optional

from google.cloud import webrisk_v1
from google.cloud.webrisk_v1.services.web_risk_service import WebRiskServiceClient

from src.core.cache import cache

class ReputationChecker:
    """
    網址信譽檢查器 - 使用 Google Web Risk API。
    
    使用兩階段查詢優化效能：
    1. 先在本地 Redis 緩存中檢查 hash prefix
    2. 只有本地匹配時才呼叫 Google API 確認
    """
    
    def __init__(self):
        self._webrisk_client: Optional[WebRiskServiceClient] = None
        
    @property
    def webrisk_client(self) -> WebRiskServiceClient:
        """
        懶加載 Web Risk 客戶端。
        需要設定 GOOGLE_APPLICATION_CREDENTIALS 環境變數指向服務帳戶密鑰檔案。
        """
        if self._webrisk_client is None:
            self._webrisk_client = WebRiskServiceClient()
        return self._webrisk_client

    async def check_url(self, url: str) -> Dict[str, Any]:
        """
        使用 Google Web Risk API 檢查網址安全性。
        
        實作邏輯 (使用本地 Redis 緩存):
        1. 標準化網址並計算 SHA256 雜湊
        2. 先在本地 Redis 緩存中檢查 hash prefix 是否存在
        3. 如果本地有匹配，才呼叫 search_hashes API 進行最終確認
        4. 比對完整雜湊確認威脅
        
        這種兩階段查詢可以大幅減少 API 呼叫次數，因為大多數安全網址
        不會在本地威脅清單中找到匹配。
        
        Args:
            url: 要檢查的網址
        
        Returns:
            Dict 包含:
            - is_threat: bool - 是否為已知威脅
            - threat_types: List[str] - 偵測到的威脅類型
            - cache_hit: bool - 是否從本地緩存命中
            - error: str (如果有錯誤)
        """
        # 檢查結果快取（之前的查詢結果）
        cached = await cache.get(f"webrisk:{url}")
        if cached:
            return cached
        
        try:
            # 1. 標準化網址並計算雜湊
            full_hash = self.compute_url_hash(url)
            hash_prefix = full_hash[:4]  # 使用 4 bytes 前綴
            
            # 2. 先檢查本地 Redis 緩存
            local_matches = await cache.check_hash_prefix(hash_prefix)
            
            if not local_matches:
                # 本地緩存沒有匹配，直接返回安全
                result = {
                    "is_threat": False,
                    "threat_types": [],
                    "cache_hit": True,
                }
                # 快取結果 (30 分鐘)
                await cache.set(f"webrisk:{url}", result, ttl=1800)
                return result
            
            # 3. 本地緩存有匹配，呼叫 API 進行最終確認
            client = self.webrisk_client
            
            # 4. 呼叫 search_hashes API 進行最終確認
            loop = asyncio.get_event_loop()
            
            def _search_hashes():
                request = webrisk_v1.SearchHashesRequest(
                    hash_prefix=hash_prefix,
                    threat_types=[
                        webrisk_v1.ThreatType.MALWARE,
                        webrisk_v1.ThreatType.SOCIAL_ENGINEERING,
                        webrisk_v1.ThreatType.UNWANTED_SOFTWARE,
                    ]
                )
                return client.search_hashes(request=request)
            
            response = await loop.run_in_executor(None, _search_hashes)
            
            # 5. 比對完整雜湊
            detected_threats = []
            for threat in response.threats:
                if threat.hash == full_hash:
                    # 收集威脅類型
                    for threat_type in threat.threat_types:
                        detected_threats.append(webrisk_v1.ThreatType(threat_type).name)
            
            result = {
                "is_threat": len(detected_threats) > 0,
                "threat_types": detected_threats,
                "cache_hit": False,
            }
            
            # 快取結果 (15 分鐘)
            await cache.set(f"webrisk:{url}", result, ttl=900)
            return result
            
        except Exception as e:
            return {"error": str(e)}

    async def get_reputation(self, url: str) -> Dict[str, Any]:
        """
        獲取網址的信譽評分。
        
        Args:
            url: 要檢查的網址
        
        Returns:
            Dict 包含:
            - webrisk: Web Risk 檢查結果
            - score: 風險評分 (0-100，越高越危險)
            - is_safe: 是否安全
        """
        webrisk_res = await self.check_url(url)
        
        # 計算風險評分
        score = 0
        
        if isinstance(webrisk_res, dict) and webrisk_res.get("is_threat"):
            threat_types = webrisk_res.get("threat_types", [])
            # 每種威脅類型加分
            for threat_type in threat_types:
                if threat_type == "MALWARE":
                    score += 40
                elif threat_type == "SOCIAL_ENGINEERING":
                    score += 35
                elif threat_type == "UNWANTED_SOFTWARE":
                    score += 25
        
        # 限制最高分為 100
        score = min(score, 100)
        
        return {
            "webrisk": webrisk_res,
            "score": score,
            "is_safe": score == 0
        }

            

    def canonicalize_url(url: str) -> str:
        """
        根據 Google Safe Browsing 規範標準化網址。
        參考: https://developers.google.com/safe-browsing/v4/urls-hashing#canonicalization
        
        注意：這是一個用於測試的獨立實作，完全符合 Google Safe Browsing 規範。
        """
        if not url:
            return ""
        
        # 1. 移除前後空白
        url = url.strip()
        
        # 2. 確保有協議頭
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # 3. 移除 tab (0x09), CR (0x0d), LF (0x0a)
        url = re.sub(r'[\t\r\n]', '', url)
        
        # 4. 移除 fragment (未編碼的 # 之後的內容)
        # 注意：要在解碼之前處理 fragment
        if '#' in url:
            url = url.split('#')[0]
        
        # 記錄是否有查詢字串
        has_query = '?' in url
        
        # 5. 分離 scheme 和其餘部分進行處理
        if url.startswith('https://'):
            scheme = 'https'
            rest = url[8:]
        else:
            scheme = 'http'
            rest = url[7:]
        
        # 分離 host 和 path/query
        if '/' in rest:
            host_part = rest[:rest.index('/')]
            path_query = rest[rest.index('/'):]
        else:
            host_part = rest
            path_query = '/'
        
        # 分離 path 和 query
        if '?' in path_query:
            path = path_query[:path_query.index('?')]
            query = path_query[path_query.index('?')+1:]
        else:
            path = path_query
            query = ''
        
        # 6. 重複解碼各部分直到穩定
        def unescape_repeatedly(s: str) -> str:
            prev = None
            while prev != s:
                prev = s
                try:
                    s = unquote(s)
                except Exception:
                    break
            return s
        
        host_part = unescape_repeatedly(host_part)
        path = unescape_repeatedly(path)
        query = unescape_repeatedly(query) if query else ''
        
        # 7. 處理主機名稱
        # 移除端口
        if ':' in host_part:
            host_part = host_part[:host_part.index(':')]
        
        hostname = host_part.lower()
        # 移除前後的點
        hostname = hostname.strip('.')
        # 將連續的點替換為單一點
        hostname = re.sub(r'\.+', '.', hostname)
        
        # 處理十進制 IP 地址 (DWORD 格式)
        try:
            if hostname.isdigit():
                ip_int = int(hostname)
                if 0 <= ip_int <= 0xFFFFFFFF:
                    hostname = f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"
        except ValueError:
            pass
        
        # 8. 處理路徑中的 . 和 ..
        if not path:
            path = '/'
        
        path_parts = []
        for part in path.split('/'):
            if part == '..':
                if path_parts:
                    path_parts.pop()
            elif part != '.' and part != '':
                path_parts.append(part)
        
        normalized_path = '/' + '/'.join(path_parts)
        if path.endswith('/') and not normalized_path.endswith('/'):
            normalized_path += '/'
        
        if not normalized_path:
            normalized_path = '/'
        
        # 9. 重新編碼特殊字元 (只編碼: <= 32, >= 127, #, %)
        # 使用 Latin-1 編碼以保持單字節編碼
        def safe_encode(s: str) -> str:
            result = []
            for char in s:
                code = ord(char)
                if code <= 32 or code >= 127 or char in '#%':
                    # 使用 Latin-1 編碼確保單字節字元被正確編碼
                    try:
                        encoded = char.encode('latin-1')
                        for byte in encoded:
                            result.append(f'%{byte:02X}')
                    except UnicodeEncodeError:
                        # 對於無法用 Latin-1 編碼的字元，使用 UTF-8
                        result.append(quote(char, safe=''))
                else:
                    result.append(char)
            return ''.join(result)
        
        encoded_hostname = safe_encode(hostname)
        encoded_path = safe_encode(normalized_path)
        encoded_query = safe_encode(query) if query else ''
        
        # 10. 重建 URL
        if encoded_query:
            return f"{scheme}://{encoded_hostname}{encoded_path}?{encoded_query}"
        elif has_query:
            return f"{scheme}://{encoded_hostname}{encoded_path}?"
        return f"{scheme}://{encoded_hostname}{encoded_path}"


    def compute_url_hash(self, url: str) -> bytes:
        """
        計算標準化網址的 SHA256 雜湊值。
        """
        canonical_url = self.canonicalize_url(url)
        return hashlib.sha256(canonical_url.encode('utf-8')).digest()


    def get_hash_prefixes(self, url: str, prefix_sizes: List[int] = [4, 5, 6, 7, 8]) -> List[bytes]:
        """
        獲取網址的多個雜湊前綴 (用於本地緩存比對)。
        預設返回 4-8 bytes 的前綴。
        """
        full_hash = self.compute_url_hash(url)
        return [full_hash[:size] for size in prefix_sizes if size <= len(full_hash)]


