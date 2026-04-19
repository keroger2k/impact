import asyncio
from playwright.async_api import async_playwright
import os

async def verify():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        context = await browser.new_context()
        page = await context.new_page()

        # Login (Impact token is mocked in DEV_MODE usually, but we need the cookie)
        await page.goto("http://localhost:3000/login")
        await page.fill('input[name="username"]', "admin")
        await page.fill('input[name="password"]', "admin")
        await page.click('button[type="submit"]')
        await page.wait_for_url("http://localhost:3000/dashboard")

        # Go to IPAM
        await page.goto("http://localhost:3000/ipam")

        # Click Refresh Discovery
        await page.click('#refresh-btn')
        # Wait for toast and tree load
        await page.wait_for_timeout(5000)

        await page.screenshot(path="ipam_dashboard_final.png", full_page=True)
        await browser.close()

if __name__ == "__main__":
    asyncio.run(verify())
