import { chromium } from 'playwright';

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1600, height: 900 } });
  const page = await ctx.newPage();

  const consoleErrs = [];
  const pageErrs = [];
  const ipamResponses = [];
  page.on('console', m => { if (m.type() === 'error') consoleErrs.push(m.text()); });
  page.on('pageerror', e => pageErrs.push(e.toString()));
  page.on('response', async r => {
    if (r.url().includes('/api/ipam/')) {
      ipamResponses.push(`${r.status()} ${r.url()}`);
    }
  });

  await page.goto('http://127.0.0.1:8765/login');
  await page.fill('input[name="username"]', 'dfadf');
  await page.fill('input[name="password"]', 'dfadf');
  await page.click('button[type="submit"]');
  await page.waitForURL(/\/dashboard/, { timeout: 10000 }).catch(() => {});

  await page.goto('http://127.0.0.1:8765/ipam');
  // Wait long enough for SSE refresh to complete
  await page.waitForTimeout(15000);

  const resultsText = (await page.textContent('#ipam-results').catch(() => '')).slice(0, 400);
  const refreshLog = (await page.textContent('#ipam-refresh-log').catch(() => '')).slice(0, 800);
  const currentDataHasIpv4 = await page.evaluate(() => {
    return (typeof currentIPAMData !== 'undefined' && currentIPAMData) ? (currentIPAMData.ipv4 || []).length : -1;
  });

  console.log(JSON.stringify({ currentDataIpv4Count: currentDataHasIpv4, resultsText, refreshLog, pageErrs, consoleErrs, ipamResponses }, null, 2));

  await page.screenshot({ path: '/tmp/ipam-after.png', fullPage: false });
  await browser.close();
})();
