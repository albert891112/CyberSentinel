import asyncio
import sys
import os

sys.path.append(os.getcwd())

from app.reflex.engine import ReflexEngine

async def main():
    engine = ReflexEngine()
    
    test_urls = [
        "https://www.google.com",
        "http://paypal-secure-login.com.evil.xyz", # High static risk
        "https://newly-registered-domain-test.com" # Potential enrichment risk (simulated)
    ]
    
    print("🚀 Starting Reflex Layer Verification...\n")
    
    for url in test_urls:
        print(f"Analyzing: {url}...")
        result = await engine.analyze(url)
        print(f"Verdict: {result['verdict']} (Score: {result['risk_score']})")
        print(f"Details: {result}\n")
        
    print("🔄 Testing Cache (should be instant)...")
    cached_result = await engine.analyze(test_urls[0])
    print(f"Source: {cached_result.get('source')}")

if __name__ == "__main__":
    asyncio.run(main())
