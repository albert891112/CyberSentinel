import asyncio
import os
from redis import asyncio as aioredis
from qdrant_client import QdrantClient
from qdrant_client.http.models import Distance, VectorParams
from dotenv import load_dotenv

load_dotenv()

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")

async def verify_redis():
    print(f"[*] Connecting to Redis at {REDIS_URL}...")
    try:
        redis = aioredis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
        await redis.set("ping", "pong")
        value = await redis.get("ping")
        if value == "pong":
            print("[+] Redis Check: SUCCESS")
        else:
            print("[-] Redis Check: FAILED (Value mismatch)")
        await redis.close()
    except Exception as e:
        print(f"[-] Redis Check: FAILED ({e})")

def verify_qdrant():
    print(f"[*] Connecting to Qdrant at {QDRANT_URL}...")
    try:
        client = QdrantClient(url=QDRANT_URL)
        collections = client.get_collections()
        print(f"[+] Qdrant Check: SUCCESS (Found {len(collections.collections)} collections)")
        
        # Ensure brand_vectors collection exists
        collection_name = "brand_vectors"
        exists = any(c.name == collection_name for c in collections.collections)
        if not exists:
            print(f"[*] Creating '{collection_name}' collection...")
            client.create_collection(
                collection_name=collection_name,
                vectors_config=VectorParams(size=512, distance=Distance.COSINE),
            )
            print(f"[+] Collection '{collection_name}' created.")
        else:
            print(f"[+] Collection '{collection_name}' already exists.")
            
    except Exception as e:
        print(f"[-] Qdrant Check: FAILED ({e})")


async def verify_browserless():
    import httpx
    url = "http://localhost:3000"
    print(f"[*] Connecting to Browserless at {url}...")
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                print(f"[+] Browserless Check: SUCCESS (Status 200)")
            else:
                print(f"[-] Browserless Check: FAILED (Status {resp.status_code})")
    except Exception as e:
        print(f"[-] Browserless Check: FAILED ({e})")

async def main():
    print("=== CyberSentinel Infrastructure Verification ===\n")
    await verify_redis()
    print("-" * 30)
    verify_qdrant()
    print("-" * 30)
    await verify_browserless()
    print("\n=== Verification Complete ===")

if __name__ == "__main__":
    asyncio.run(main())
