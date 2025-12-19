import asyncio
import asyncwhois
import dns.asyncresolver
from datetime import datetime
from urllib.parse import urlparse

class EnrichmentModule:
    async def get_domain_age(self, domain: str) -> int:
        """Returns domain age in days. Returns -1 if lookup fails."""
        try:
            result = await asyncwhois.aio_lookup(domain)
            creation_date = result.parser_output.get('created')
            
            # Handle list of dates (some registrars return list)
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
                
            if creation_date:
                if isinstance(creation_date, str):
                     # Try parsing common formats if it returns string
                     pass 
                
                # Assume creation_date is datetime object if successful
                if isinstance(creation_date, datetime):
                     delta = datetime.now() - creation_date
                     return delta.days
            return -1
        except Exception as e:
            # print(f"Whois lookup failed: {e}")
            return -1

    async def check_dns(self, domain: str) -> bool:
        """Checks if domain has valid A records."""
        try:
             resolver = dns.asyncresolver.Resolver()
             await resolver.resolve(domain, 'A')
             return True
        except Exception:
             return False

    async def enrich(self, url: str) -> dict:
        parsed = urlparse(url)
        domain = parsed.netloc
        
        age_days = await self.get_domain_age(domain)
        has_dns = await self.check_dns(domain)
        
        enrichment_risk = 0
        if age_days != -1 and age_days < 30:
            enrichment_risk += 80 # New domain high risk
            
        return {
            "domain_age_days": age_days,
            "has_valid_dns": has_dns,
            "enrichment_risk_score": enrichment_risk
        }
