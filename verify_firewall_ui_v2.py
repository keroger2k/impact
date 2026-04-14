import asyncio
from playwright.async_api import async_playwright

async def verify():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        context = await browser.new_context()
        page = await context.new_page()

        # In this app, the token is passed via cookie or header.
        # The base.html uses hx-headers with the token.
        # But for the initial page load, it needs to be authenticated.
        # Since DEV_MODE is on, we can try to hit /login first if needed,
        # or directly set a cookie if we knew the name.

        # Let's try to navigate and see if it redirects.
        await page.goto("http://localhost:8000/firewall")

        # If redirected to login, perform login (in DEV_MODE any creds work)
        if "/login" in page.url:
            await page.fill('input[name="username"]', 'admin')
            await page.fill('input[name="password"]', 'admin')
            await page.click('button[type="submit"]')
            await page.wait_for_url("**/dashboard")
            # Now go back to firewall
            await page.goto("http://localhost:8000/firewall")

        # Click on Interface Inventory button (it's inside the Firewall view)
        await page.wait_for_selector("button:has-text('Interface Inventory')")
        await page.click("button:has-text('Interface Inventory')")

        # Wait for the table and content
        await page.wait_for_selector("table")
        await asyncio.sleep(1) # Wait for HTMX to finish rendering

        # Take a screenshot
        await page.screenshot(path="firewall_interfaces_final.png")

        # Print info
        headers = await page.query_selector_all("th")
        header_texts = [await h.inner_text() for h in headers]
        print(f"Headers: {header_texts}")

        zones = await page.query_selector_all(".badge")
        zone_texts = [await z.inner_text() for z in zones]
        print(f"Zones found: {zone_texts}")

        await browser.close()

if __name__ == "__main__":
    asyncio.run(verify())
