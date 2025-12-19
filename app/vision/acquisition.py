import asyncio
import random
from playwright.async_api import async_playwright
from app.config import settings

class PageAcquirer:
    def __init__(self):
        self.browserless_url = settings.BROWSERLESS_URL

    async def _simulate_human_behavior(self, page):
        """Simulate mouse movements and scrolls to bypass basic bot detection."""
        try:
            # Random mouse movements
            for _ in range(3):
                x = random.randint(100, 1000)
                y = random.randint(100, 1000)
                await page.mouse.move(x, y)
                await asyncio.sleep(random.uniform(0.1, 0.3))
            
            # Simple scroll
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight / 2)")
            await asyncio.sleep(0.5)
        except Exception:
            pass # Ignore errors during simulation

    async def capture(self, url: str) -> dict:
        """
        Captures screenshot and HTML content of the URL.
        Returns a dict with 'screenshot' (bytes) and 'html' (str).
        """
        async with async_playwright() as p:
            try:
                browser = await p.chromium.connect_over_cdp(self.browserless_url)
                context = await browser.new_context(
                    viewport={'width': 1280, 'height': 720},
                    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36'
                )
                page = await context.new_page()
                
                await page.goto(url, timeout=30000, wait_until='networkidle')
                await self._simulate_human_behavior(page)
                
                screenshot = await page.screenshot(type='jpeg', quality=80)
                html = await page.content()
                
                await context.close()
                await browser.close()
                
                return {
                    "screenshot": screenshot,
                    "html": html,
                    "status": "success"
                }
            except Exception as e:
                return {
                    "status": "error",
                    "error": str(e),
                    "screenshot": None,
                    "html": None
                }
