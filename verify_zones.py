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

        # Go to Firewall Ops
        await page.click('a:has-text("Firewall Ops")')
        await page.wait_for_selector('button:has-text("Interface Inventory")')

        # Click Interface Inventory
        await page.click('button:has-text("Interface Inventory")')
        await page.wait_for_selector('th:has-text("Zone")')

        # Take screenshot
        await page.screenshot(path="firewall_interfaces_zones.png")
        print("Screenshot saved to firewall_interfaces_zones.png")

        await browser.close()

if __name__ == "__main__":
    asyncio.run(main())
