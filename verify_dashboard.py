import asyncio
from playwright.async_api import async_playwright
import os

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        context = await browser.new_context(viewport={'width': 1920, 'height': 1080})
        page = await context.new_page()

        # Login
        await page.goto("http://localhost:8000/login")
        await page.fill('input[name="username"]', "admin")
        await page.fill('input[name="password"]', "admin")
        await page.click('button[type="submit"]')

        # Wait for dashboard
        await page.wait_for_selector('.kpi-card')

        # Take screenshot of the whole dashboard
        await page.screenshot(path="dashboard_improved.png")
        print("Screenshot saved to dashboard_improved.png")

        await browser.close()

if __name__ == "__main__":
    asyncio.run(main())
