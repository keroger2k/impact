import asyncio
from playwright.async_api import async_playwright

async def verify():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        # Create a context with the dev token in localStorage
        context = await browser.new_context()
        page = await context.new_page()

        # Navigate to the app
        await page.goto("http://localhost:8000")

        # Set dev token in localStorage to bypass login
        await page.evaluate("localStorage.setItem('impact_token', 'dev-local-token-impact-ii')")
        await page.reload()

        # Click on Firewall Ops
        await page.click("a:has-text('Firewall Ops')")

        # Click on Interface Inventory
        await page.click("button:has-text('Interface Inventory')")

        # Wait for the table to load
        await page.wait_for_selector("table")

        # Take a screenshot
        await page.screenshot(path="firewall_interfaces_check.png")

        # Check for the Zone column and content
        headers = await page.query_selector_all("th")
        header_texts = [await h.inner_text() for h in headers]
        print(f"Headers: {header_texts}")

        zones = await page.query_selector_all(".badge")
        zone_texts = [await z.inner_text() for z in zones]
        print(f"Zones found: {zone_texts}")

        await browser.close()

if __name__ == "__main__":
    asyncio.run(verify())
