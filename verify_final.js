const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.setViewportSize({ width: 1440, height: 2500 });

  await page.goto('http://localhost:8000/login');
  await page.fill('input[name="username"]', 'admin');
  await page.fill('input[name="password"]', 'admin');
  await page.click('button[type="submit"]');
  await page.waitForURL('**/dashboard');
  await page.waitForTimeout(1000);
  await page.screenshot({ path: 'screenshots/dashboard_final.png', fullPage: true });

  await page.click('a:has-text("IPAM Dashboard")');
  await page.waitForTimeout(1000);
  await page.screenshot({ path: 'screenshots/ipam_final.png', fullPage: true });

  await page.click('a:has-text("Devices")');
  await page.waitForTimeout(1000);
  await page.screenshot({ path: 'screenshots/devices_final.png', fullPage: true });

  await browser.close();
})();
