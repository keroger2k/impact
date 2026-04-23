import { test, expect } from '@playwright/test';

test('verify IPAM search functionality', async ({ page }) => {
  // Login
  await page.goto('http://localhost:3000/login');
  await page.fill('input[name="username"]', 'admin');
  await page.fill('input[name="password"]', 'admin');
  await page.click('button[type="submit"]');
  await page.waitForURL('**/dashboard');

  // Go to IPAM
  await page.click('a:has-text("IPAM Dashboard")');
  await page.waitForSelector('.table-container');

  const filterInput = page.locator('#ipam-filter');

  // 1. Test IP containment search
  await filterInput.fill('10.10.1.5');
  await page.waitForTimeout(500); // Debounce
  await expect(page.locator('text=10.10.1.0/24')).toBeVisible();
  // Parent should also be visible (ancestor)
  await expect(page.locator('text=10.10.0.0/16')).toBeVisible();

  // 2. Test scoped search type:tunnel
  await filterInput.fill('type:tunnel');
  await page.waitForTimeout(500);
  // Tunnel network should be visible
  await expect(page.locator('text=Tunnel Network (2 endpoints)')).toBeVisible();
  // Standard subnet should be hidden
  await expect(page.locator('text=10.10.1.0/24')).not.toBeVisible();

  // 3. Test vlan scoped search
  await filterInput.fill('vlan:200');
  await page.waitForTimeout(500);
  await expect(page.locator('text=10.10.1.0/24')).toBeVisible();

  // 4. Test ancestor preservation opacity
  const ancestor = page.locator('text=10.10.0.0/16').locator('xpath=./ancestor::div[contains(@class, "ipam-node-item")][1]');
  await expect(ancestor).toHaveCSS('opacity', '0.55');

  // 5. Test child preservation when parent matches
  await filterInput.fill('cidr:10.10.100.0/24');
  await page.waitForTimeout(500);
  await expect(page.locator('text=10.10.100.1')).toBeVisible(); // child of matched tunnel_group
});
