import { test, expect } from '@playwright/test';

test('verify redesign', async ({ page }) => {
  await page.goto('http://localhost:3000/login');
  await page.screenshot({ path: 'screenshots/login_v4.png' });

  await page.fill('input[name="username"]', 'admin');
  await page.fill('input[name="password"]', 'admin');
  await page.click('button[type="submit"]');

  // Wait for dashboard specifically
  await page.waitForURL('**/dashboard');
  await page.waitForSelector('.health-bar');
  await page.screenshot({ path: 'screenshots/dashboard_v4.png', fullPage: true });

  // Check sidebar categories
  const sidebar = page.locator('#sidebar');
  await expect(sidebar).toContainText('Network Ops');
  await expect(sidebar).toContainText('Security & Compliance');

  // Toggle sidebar using the button in the topbar
  await page.click('header button.btn-action');
  await page.waitForTimeout(500);
  await page.screenshot({ path: 'screenshots/dashboard_collapsed_v4.png' });

  await page.click('a:has-text("IPAM Dashboard")');
  await page.waitForSelector('.table-container');
  await page.screenshot({ path: 'screenshots/ipam_v4.png', fullPage: true });

  await page.click('a:has-text("Devices")');
  await page.waitForSelector('table');
  await page.screenshot({ path: 'screenshots/devices_v4.png', fullPage: true });
});
