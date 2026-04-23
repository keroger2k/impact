import { chromium } from 'playwright';

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1600, height: 900 } });
  const page = await ctx.newPage();

  const consoleErrs = [];
  const pageErrs = [];
  page.on('console', m => {
    if (m.type() === 'error') consoleErrs.push(m.text());
  });
  page.on('pageerror', e => pageErrs.push(e.toString()));

  await page.goto('http://127.0.0.1:8765/login');
  await page.fill('input[name="username"]', 'dfadf');
  await page.fill('input[name="password"]', 'dfadf');
  await page.click('button[type="submit"]');
  await page.waitForURL(/\/dashboard/, { timeout: 10000 }).catch(() => {});
  console.log('URL after login:', page.url());

  await page.goto('http://127.0.0.1:8765/devices');
  await page.waitForTimeout(2000);

  const allDevices = await page.evaluate(() => {
    return (typeof ALL_DEVICES !== 'undefined') ? (Array.isArray(ALL_DEVICES) ? ALL_DEVICES.length : 'not-array') : 'undefined';
  });
  const rowCount = await page.locator('#dev-table-body tr').count();
  const badge = await page.textContent('#dev-count-badge').catch(() => null);
  const pagingInfo = await page.textContent('#paging-info').catch(() => null);

  console.log('ALL_DEVICES length:', allDevices);
  console.log('Row count in DOM:', rowCount);
  console.log('Badge text:', badge);
  console.log('Paging info:', pagingInfo);
  console.log('Page errors:', pageErrs);
  console.log('Console errors:', consoleErrs);

  await page.screenshot({ path: '/tmp/devices-fixed.png', fullPage: false });

  await browser.close();
})();
