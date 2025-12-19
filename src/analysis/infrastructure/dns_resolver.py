import dns.asyncresolver
import dns.resolver
from typing import Dict, List, Any

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
