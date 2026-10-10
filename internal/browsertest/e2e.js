// Drives the static login page in headless Chromium. Usage: node e2e.js <pageDir> <link-fragment> <action> <json values>
const { chromium } = require('playwright');
(async () => {
  const [dir, fragment, action, values, reason, openAs] = process.argv.slice(2);
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  const base = openAs === 'http' ? process.env.PAGE_HTTP_URL : 'file://' + dir + '/index.html';
  await page.goto(base + '#' + fragment);
  if (action === 'mismatch') {
    await page.waitForSelector('#paste:not([hidden])', { timeout: 10000 });
    console.log(JSON.stringify({ msg: await page.textContent('#msg'), mainHidden: await page.$eval('#main', (e) => e.hidden), errors }));
    await browser.close();
    return;
  }
  await page.waitForSelector('#main:not([hidden])', { timeout: 10000 });
  await page.waitForTimeout(300); // let images settle
  const imgs = await page.$$eval('img.captcha', (els) => els.map((e) => ({ src: e.src.slice(0, 22), w: e.naturalWidth })));
  const fpr = await page.textContent('#d-fpr');
  const hashAfter = await page.evaluate(() => location.hash);
  if (action === 'submit') {
    const vals = JSON.parse(values);
    for (const [k, v] of Object.entries(vals)) await page.fill('#f-' + k, v);
    await page.click('#submit');
  } else {
    await page.click('#reject');
    if (reason) await page.fill('#reason', reason);
    await page.click('#reject');
  }
  await page.waitForFunction(() => /Done|failed|Rejected|Another step|refused|Stopped/.test(document.getElementById('msg').textContent), null, { timeout: 15000 });
  const msg = await page.textContent('#msg');
  console.log(JSON.stringify({ fpr, hashAfter, msg, errors, imgs }));
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
