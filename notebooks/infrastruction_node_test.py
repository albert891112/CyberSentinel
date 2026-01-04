import dns.asyncresolver
import dns.resolver
from rich import print
from typing import Dict, List, Any
import asyncio
import asyncwhois
import datetime
import os
import httpx
import json
import os
from typing import Any, Optional
from redis import asyncio as aioredis
class DNSResolver:
    def __init__(self):
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.lifetime = 5.0 # Timeout

    async def get_dns_records(self, domain: str) -> Dict[str, Any]:
        results = {
            "a_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "ttl": None
        }
        
        try:
            # A Records
            answers = await self.resolver.resolve(domain, 'A')
            results["a_records"] = [r.to_text() for r in answers]
            results["ttl"] = answers.rrset.ttl
        except Exception:
            pass

        try:
            # MX Records
            answers = await self.resolver.resolve(domain, 'MX')
            results["mx_records"] = [r.exchange.to_text() for r in answers]
        except Exception:
            pass

        try:
            # NS Records
            answers = await self.resolver.resolve(domain, 'NS')
            results["ns_records"] = [r.to_text() for r in answers]
        except Exception:
            pass
        return results

class WhoisClient:
    async def get_whois_info(self, domain: str) -> Dict[str, Any]:
        try:
            # 新版 asyncwhois API: aio_whois 回傳 (query_string, parsed_dict) 元組
            query_string, parsed_dict = await asyncwhois.aio_whois(domain)
            
            # Normalize dates
            created = parsed_dict.get("created") or parsed_dict.get("creation_date") or parsed_dict.get("registration_date")
            if isinstance(created, list):
                created = created[0]

            # Fallback: Regex on raw output
            if not created and query_string:
                import re
                # Match Creation Date: YYYY-MM-DD or similar
                match = re.search(r'(?i)(creation|registration)\s*date:\s*([0-9-]{10})', query_string)
                if match:
                    created = match.group(2)
            
            # Calculate age
            age_days = -1
            if created:
                 if isinstance(created, str):
                    try:
                        # Attempt standard ISO parsing or fuzzy
                        created_dt = datetime.datetime.fromisoformat(str(created).replace('Z', '+00:00'))
                        age_days = (datetime.datetime.now(datetime.timezone.utc) - created_dt).days
                    except:
                        pass
                 elif isinstance(created, datetime.datetime):
                     age_days = (datetime.datetime.now(created.tzinfo) - created).days

            return {
                "registrar": parsed_dict.get("registrar"),
                "created_date": str(created),
                "age_days": age_days,
                "raw": query_string
            }
        except Exception as e:
            return {"error": str(e)}

    def is_newly_registered(self, whois_data: Dict[str, Any], threshold_days: int = 30) -> bool:
        age = whois_data.get("age_days", -1)
        if age == -1:
            return False # Fail safe
        return age < threshold_days


class ReputationChecker:
    def __init__(self):
        self.vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.gsb_api_key = os.getenv("GOOGLE_SAFE_BROWSING_KEY")

    async def check_virustotal(self, url: str) -> Dict[str, Any]:
        if not self.vt_api_key:
            return {"error": "API Key Missing"}
        cache = RedisCache()
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


if __name__ == "__main__":
    resolver = DNSResolver()
    whois_client = WhoisClient()
    reputation_checker = ReputationChecker()
    result = asyncio.run(resolver.get_dns_records("example.com"))
    whois_result = asyncio.run(whois_client.get_whois_info("example.com"))  
    reputation_result = asyncio.run(reputation_checker.aggregate_reputation("example.com"))
    print(result)
    print(whois_result)
    print(reputation_result)
