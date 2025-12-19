import asyncio
import os
import sys

# Ensure src is in path
sys.path.append(os.path.join(os.path.dirname(__file__), '../../'))

from src.analysis.visual.browser import BrowserService
from src.analysis.visual.scanner import VisualScanner

async def seed_visual_db():
    print("=== Phase 3: Visual Database Seeding ===\n")
    
    # 1. Capture Reference Images
    browser = BrowserService()
    brands = {
        "google": "https://www.google.com",
        "microsoft": "https://www.microsoft.com",
        "example": "https://example.com"
    }
    
    os.makedirs("data/references", exist_ok=True)
    
    for name, url in brands.items():
        print(f"[*] Capturing reference for {name} ({url})...")
        img_bytes = await browser.capture_screenshot(url)
        if img_bytes:
            path = f"data/references/{name}.png"
            with open(path, "wb") as f:
                f.write(img_bytes)
            print(f"[+] Saved {path}")
        else:
            print(f"[-] Failed to capture {name}")
            
    # 2. Index to Qdrant
    print("\n[*] Indexing to Qdrant...")
    scanner = VisualScanner()
    
    for name in brands.keys():
        path = f"data/references/{name}.png"
        if os.path.exists(path):
            scanner.index_brand(name, path)
            
    print("\n=== Seeding Complete ===")

if __name__ == "__main__":
    asyncio.run(seed_visual_db())
