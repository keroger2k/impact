import { chromium } from 'playwright';

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1600, height: 900 } });
  const page = await ctx.newPage();

  const pageErrs = [];
  const allConsole = [];
  page.on('pageerror', e => pageErrs.push(e.toString()));
  page.on('console', m => allConsole.push(`[${m.type()}] ${m.text()}`));

  await page.goto('http://127.0.0.1:8765/login');
  await page.fill('input[name="username"]', 'dfadf');
  await page.fill('input[name="password"]', 'dfadf');
  await page.click('button[type="submit"]');
  await page.waitForURL(/\/dashboard/, { timeout: 10000 }).catch(() => {});

  // First visit: dashboard → ipam
  await page.click('a[hx-get="/ipam"]');
  await page.waitForTimeout(2000);

  // Navigate away to another page
  await page.click('a[hx-get="/dashboard"]');
  await page.waitForTimeout(1500);

  // Navigate back to ipam
  await page.click('a[hx-get="/ipam"]');
  await page.waitForTimeout(2000);

  const resultsPreview = (await page.textContent('#ipam-results').catch(() => '')).slice(0, 400);

  console.log(JSON.stringify({ resultsPreview, pageErrs, allConsole: allConsole.slice(-20) }, null, 2));
  await page.screenshot({ path: '/tmp/ipam-renav.png' });
  await browser.close();
})();
