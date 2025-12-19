import asyncio
import os
import sys

# Ensure src is in path
sys.path.append(os.path.join(os.path.dirname(__file__), '../../'))

from src.analysis.visual.browser import BrowserService
from src.analysis.visual.scanner import VisualScanner

async def verify_visual():
    print("=== Phase 3: Visual Verification ===\n")
    
    target_url = "https://example.com"
    print(f"[*] Target URL: {target_url}")
    
    # 1. Capture
    browser = BrowserService()
    print("[*] Taking screenshot...")
    img_bytes = await browser.capture_screenshot(target_url)
    
    if not img_bytes:
        print("[-] Screenshot failed.")
        return

    # 2. Compare
    print("[*] Comparing with database...")
    scanner = VisualScanner()
    result = scanner.compare(img_bytes)
    
    print(f"\n[+] Result: {result}")
    
    if result["match"] == "example" and result["score"] > 0.9:
         print("[+] SUCCESS: Correctly identified 'example' brand.")
    else:
         print(f"[-] WARNING: Match result unexpected (Score: {result['score']})")

if __name__ == "__main__":
    asyncio.run(verify_visual())
