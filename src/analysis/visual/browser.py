import os
import asyncio
from playwright.async_api import async_playwright
from typing import Optional

class BrowserService:
    def __init__(self):
        self.browserless_url = os.getenv("BROWSERLESS_URL", "ws://localhost:3000")

    async def capture_screenshot(self, url: str) -> Optional[bytes]:
        """
        Captures a screenshot of the given URL using remote browser.
        """
        async with async_playwright() as p:
            try:
                # Connect to Browserless
                browser = await p.chromium.connect_over_cdp(self.browserless_url)
                context = await browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                    viewport={"width": 1280, "height": 720}
                )
                page = await context.new_page()
                
                # Go to URL
                print(f"[Browser] Navigating to {url}...")
                await page.goto(url, wait_until="networkidle", timeout=30000)
                
                # Screenshot
                screenshot_bytes = await page.screenshot(full_page=False)
                
                await context.close()
                await browser.close()
                return screenshot_bytes

            except Exception as e:
                print(f"[Browser Error] {e}")
                return None

    async def get_page_text(self, url: str) -> str:
         async with async_playwright() as p:
            try:
                browser = await p.chromium.connect_over_cdp(self.browserless_url)
                page = await browser.new_page()
                await page.goto(url, wait_until="domcontentloaded", timeout=30000)
                text = await page.inner_text("body")
                await browser.close()
                return text
            except Exception as e:
                print(f"[Browser Error] {e}")
                return ""
