import asyncwhois
import datetime
from typing import Dict, Any

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
