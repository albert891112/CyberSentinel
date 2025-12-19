import httpx
import os
import asyncio
from typing import Dict, Any
from src.core.cache import cache

class ReputationChecker:
    def __init__(self):
        self.vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.gsb_api_key = os.getenv("GOOGLE_SAFE_BROWSING_KEY")

    async def check_virustotal(self, url: str) -> Dict[str, Any]:
        if not self.vt_api_key:
            return {"error": "API Key Missing"}

        # Check Cache
        cached = await cache.get(f"vt:{url}")
        if cached:
            return cached

        # VT API Logic (Simplified for V3)
        # We need URL ID first (base64)
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        
        headers = {"x-apikey": self.vt_api_key}
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(endpoint, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    result = {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0)
                    }
                    await cache.set(f"vt:{url}", result, ttl=3600) # Cache 1 hour
                    return result
                return {"error": f"Status {resp.status_code}"}
            except Exception as e:
                return {"error": str(e)}

    async def aggregate_reputation(self, url: str) -> Dict[str, Any]:
        # For now, just VT. Can add GSB and AbuseIPDB similarly.
        vt_res = await self.check_virustotal(url)
        
        score = 0
        if isinstance(vt_res, dict) and "malicious" in vt_res:
            if vt_res["malicious"] > 2:
                score = 100 # High confidence
            elif vt_res["malicious"] > 0:
                score = 50
        
        return {
            "vt": vt_res,
            "score": score
        }
