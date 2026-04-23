import { chromium } from 'playwright';

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1600, height: 900 } });
  const page = await ctx.newPage();

  const pageErrs = [];
  page.on('pageerror', e => pageErrs.push(e.toString()));

  await page.goto('http://127.0.0.1:8765/login');
  await page.fill('input[name="username"]', 'dfadf');
  await page.fill('input[name="password"]', 'dfadf');
  await page.click('button[type="submit"]');
  await page.waitForURL(/\/dashboard/, { timeout: 10000 }).catch(() => {});

  // Nav: dashboard → ipam → dashboard → ipam (exercises re-nav)
  await page.click('a[hx-get="/ipam"]');
  await page.waitForTimeout(1500);
  await page.click('a[hx-get="/dashboard"]');
  await page.waitForTimeout(1000);
  await page.click('a[hx-get="/ipam"]');
  await page.waitForTimeout(2000);

  const rootCount = await page.locator('#ipam-results .ipam-node-item').count();
  console.log(JSON.stringify({ rootCount, pageErrs }, null, 2));
  await page.screenshot({ path: '/tmp/ipam-working.png' });
  await browser.close();
})();
