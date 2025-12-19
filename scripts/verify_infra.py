import asyncio
import redis.asyncio as redis
from qdrant_client import QdrantClient
from playwright.async_api import async_playwright
import sys
import os

# Add project root to sys.path
sys.path.append(os.getcwd())

from app.config import settings

async def check_redis():
    try:
        r = redis.from_url(settings.REDIS_URL)
        await r.ping()
        print("✅ Redis Connection Successful")
    except Exception as e:
        print(f"❌ Redis Connection Failed: {e}")

async def check_qdrant():
    try:
        # QdrantClient is synchronous by default unless using AsyncQdrantClient, but simple check is fine
        client = QdrantClient(url=settings.QDRANT_URL)
        client.get_collections()
        print("✅ Qdrant Connection Successful")
    except Exception as e:
        print(f"❌ Qdrant Connection Failed: {e}")

async def check_browserless():
    try:
        async with async_playwright() as p:
            # Connect to browserless
            # Note: connect_over_cdp expects the ws endpoint
            browser = await p.chromium.connect_over_cdp(settings.BROWSERLESS_URL)
            print("✅ Browserless Connection Successful")
            await browser.close()
    except Exception as e:
        print(f"❌ Browserless Connection Failed: {e}")

async def main():
    print("Starting Infrastructure Check...")
    await check_redis()
    await check_qdrant()
    await check_browserless()

if __name__ == "__main__":
    asyncio.run(main())
