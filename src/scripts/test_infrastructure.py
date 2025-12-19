import asyncio
import os
import sys

# Ensure src is in path
sys.path.append(os.path.join(os.path.dirname(__file__), '../../'))

from src.analysis.infrastructure.dns_resolver import DNSResolver
from src.analysis.infrastructure.whois_client import WhoisClient
from src.analysis.infrastructure.reputation import ReputationChecker
from src.core.cache import cache

async def test_infrastructure():
    print("=== Phase 2 Integration Test ===\n")
    domain = "example.com"
    
    # 1. Test DNS
    print(f"[*] Testing DNS for {domain}...")
    resolver = DNSResolver()
    dns_res = await resolver.get_dns_records(domain)
    print(f"    A Records: {dns_res.get('a_records')}")
    if dns_res.get('a_records'):
        print("[+] DNS Check: SUCCESS")
    else:
        print("[-] DNS Check: FAILED")
    
    # 2. Test Whois
    print(f"\n[*] Testing Whois for {domain}...")
    whois = WhoisClient()
    whois_res = await whois.get_whois_info(domain)
    print(f"    Created: {whois_res.get('created_date')}")
    print(f"    Age Days: {whois_res.get('age_days')}")
    if whois_res.get('created_date') is None:
         print(f"    [DEBUG] Raw Keys: {list(whois_res.get('raw', {})) if isinstance(whois_res.get('raw'), dict) else 'Raw is string'}")
    
    if whois_res.get('age_days', 0) > 365:
         print("[+] Whois Check: SUCCESS (Old domain)")
    else:
         print("[-] Whois Check: WARNING (Might be parsing issue or new domain)")

    # 3. Test Redis Cache
    print(f"\n[*] Testing Redis Cache...")
    await cache.set("test_key", {"foo": "bar"})
    val = await cache.get("test_key")
    if val == {"foo": "bar"}:
        print("[+] Redis Cache: SUCCESS")
    else:
        print(f"[-] Redis Cache: FAILED (Got {val})")

    # 4. Test Reputation (Mock if no key)
    print(f"\n[*] Testing Reputation (VirusTotal)...")
    if not os.getenv("VIRUSTOTAL_API_KEY"):
        print("    [!] No VT API Key found in .env, skipping real API call.")
    else:
        rep = ReputationChecker()
        res = await rep.aggregate_reputation("https://google.com")
        print(f"    Result: {res}")

    await cache.close()

if __name__ == "__main__":
    asyncio.run(test_infrastructure())
