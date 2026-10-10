// Drives the static login page in headless Chromium.
// Usage: node e2e.js <pageDir> <link-fragment> <action> <json values> <reason> <openAs>
// Actions: submit | reject | refuse | probe | csp | emptysubmit | inert
const { chromium } = require('playwright');
(async () => {
  const [dir, fragment, action, values, reason, openAs] = process.argv.slice(2);
  const browser = await chromium.launch();
  const context = await browser.newContext({ ignoreHTTPSErrors: true }); // tests serve the page over a self-signed https
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  const base = openAs === 'http' ? process.env.PAGE_HTTP_URL : 'file://' + dir + '/index.html';
  const out = (extra) => console.log(JSON.stringify(Object.assign({ errors }, extra)));
  const text = (sel) => page.textContent(sel);
  const hidden = (sel) => page.$eval(sel, (e) => e.hidden);

  await page.goto(base + (fragment ? '#' + fragment : ''));

  if (action === 'inert') {
    // a file failed its integrity check: the page must not come to life
    await page.waitForTimeout(1200);
    out({ mainHidden: await hidden('#main'), pasteHidden: await hidden('#paste') });
    await browser.close();
    return;
  }

  if (action === 'refuse') {
    // the page must refuse the link: no form, the paste box instead, and an explanation
    await page.waitForSelector('#paste:not([hidden])', { timeout: 10000 });
    out({ msg: await text('#msg'), mainHidden: await hidden('#main'), hashAfter: await page.evaluate(() => location.hash) });
    await browser.close();
    return;
  }

  await page.waitForSelector('#main:not([hidden])', { timeout: 10000 });
  await page.waitForTimeout(300); // let images settle
  const imgs = await page.$$eval('img.captcha', (els) => els.map((e) => ({ src: e.src.slice(0, 22), w: e.naturalWidth })));
  const state = {
    fpr: await text('#d-fpr'),
    code: await text('#d-code'),
    title: await page.title(),
    hashAfter: await page.evaluate(() => location.hash),
    submitDisabledBefore: await page.$eval('#submit', (e) => e.disabled),
    autocomplete: await page.$$eval('#fields input', (els) => els.map((e) => e.autocomplete)),
    imgs,
  };

  if (action === 'probe') {
    await page.check('#verified');
    state.submitDisabledAfter = await page.$eval('#submit', (e) => e.disabled);
    await page.uncheck('#verified');
    state.submitDisabledUnchecked = await page.$eval('#submit', (e) => e.disabled);
    out(state);
    await browser.close();
    return;
  }

  if (action === 'csp') {
    // after the link is accepted, connections must be limited to the tunnel origin only
    const res = await page.evaluate(async () => {
      let violated = false;
      document.addEventListener('securitypolicyviolation', () => { violated = true; });
      let otherBlocked = false;
      try { await fetch('http://other.invalid/steal', { mode: 'no-cors' }); } catch (e) { otherBlocked = true; }
      await new Promise((r) => setTimeout(r, 50));
      return { violated, otherBlocked };
    });
    out(Object.assign(state, res));
    await browser.close();
    return;
  }

  if (action === 'emptysubmit') {
    // open the reject box, then press Submit with empty fields: nothing must be sent
    await page.check('#verified');
    await page.click('#reject');
    await page.click('#submit');
    await page.waitForTimeout(500);
    state.msg = await text('#msg');
    state.fieldsDisabled = await page.$$eval('#fields input', (els) => els.map((e) => e.disabled));
    out(state);
    await browser.close();
    return;
  }

  if (action === 'submit') {
    await page.check('#verified');
    const vals = JSON.parse(values);
    for (const [k, v] of Object.entries(vals)) await page.fill('#f-' + k, v);
    await page.click('#submit');
  } else if (action === 'reject') {
    await page.click('#reject');
    if (reason) await page.fill('#reason', reason);
    await page.click('#reject');
  }
  await page.waitForFunction(() => /Done|failed|Rejected|Another step|refused|Stopped/.test(document.getElementById('msg').textContent), null, { timeout: 15000 });
  state.msg = await text('#msg');
  state.reasonHiddenAfter = await hidden('#reject-box');
  out(state);
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
