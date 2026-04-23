import { chromium } from 'playwright';

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1600, height: 900 } });
  const page = await ctx.newPage();

  const consoleErrs = [];
  const pageErrs = [];
  const networkFails = [];
  page.on('console', m => { if (m.type() === 'error') consoleErrs.push(m.text()); });
  page.on('pageerror', e => pageErrs.push(e.toString()));
  page.on('requestfailed', r => networkFails.push(`${r.url()} -> ${r.failure()?.errorText}`));
  page.on('response', async r => {
    if (r.url().includes('/api/ipam/') && r.status() >= 400) {
      networkFails.push(`${r.url()} -> ${r.status()} ${await r.text().catch(() => '')}`);
    }
  });

  await page.goto('http://127.0.0.1:8765/login');
  await page.fill('input[name="username"]', 'dfadf');
  await page.fill('input[name="password"]', 'dfadf');
  await page.click('button[type="submit"]');
  await page.waitForURL(/\/dashboard/, { timeout: 10000 }).catch(() => {});

  await page.goto('http://127.0.0.1:8765/ipam');
  await page.waitForTimeout(3000);

  const resultsText = await page.textContent('#ipam-results').catch(() => null);
  const initialData = await page.evaluate(() => {
    return typeof currentIPAMData !== 'undefined' ? (currentIPAMData ? 'has-data' : 'null') : 'undefined';
  });

  console.log(JSON.stringify({
    initialData,
    resultsPreview: (resultsText || '').slice(0, 300),
    pageErrs,
    consoleErrs,
    networkFails,
  }, null, 2));

  await page.screenshot({ path: '/tmp/ipam-state.png', fullPage: false });
  await browser.close();
})();
