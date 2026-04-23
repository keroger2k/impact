import { chromium } from 'playwright';

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1600, height: 900 } });
  const page = await ctx.newPage();

  const pageErrs = [];
  const consoleErrs = [];
  const consoleAll = [];
  page.on('pageerror', e => pageErrs.push(e.toString()));
  page.on('console', m => {
    consoleAll.push(`[${m.type()}] ${m.text()}`);
    if (m.type() === 'error') consoleErrs.push(m.text());
  });

  await page.goto('http://127.0.0.1:8765/login');
  await page.fill('input[name="username"]', 'dfadf');
  await page.fill('input[name="password"]', 'dfadf');
  await page.click('button[type="submit"]');
  await page.waitForURL(/\/dashboard/, { timeout: 10000 }).catch(() => {});

  // Navigate using sidebar (simulates user click flow)
  await page.click('a[hx-get="/ipam"]');
  await page.waitForTimeout(3000);

  const currentDataLen = await page.evaluate(() => {
    if (typeof currentIPAMData === 'undefined') return 'undefined';
    if (currentIPAMData === null) return 'null';
    return (currentIPAMData.ipv4 || []).length;
  });
  const resultsPreview = (await page.textContent('#ipam-results').catch(() => '')).slice(0, 300);

  console.log(JSON.stringify({ currentDataLen, resultsPreview, pageErrs, consoleErrs, consoleAll: consoleAll.slice(-15) }, null, 2));
  await page.screenshot({ path: '/tmp/ipam-nav.png' });
  await browser.close();
})();
