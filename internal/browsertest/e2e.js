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
  let requestBody = ''; // what the page posted to /submit, captured on the wire
  page.on('request', (r) => { if (r.method() === 'POST' && /\/submit(\?|$)/.test(r.url())) requestBody = r.postData() || ''; });
  page.on('pageerror', (e) => errors.push(String(e)));
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  const base = openAs === 'http' ? process.env.PAGE_HTTP_URL : 'file://' + dir + '/index.html';
  const out = (extra) => console.log(JSON.stringify(Object.assign({ errors, requestBody }, extra)));
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

  // ---- unlocking: the link's parameters are encrypted and the page needs the long-period code ----
  const unlockActions = ['locked', 'unlock-submit', 'unlock-submit-expect-fail', 'unlock-wrong-then-right', 'unlock-expect-refused'];
  if (unlockActions.includes(action)) {
    await page.waitForSelector('#unlock:not([hidden])', { timeout: 10000 });
    const view = async (extra) => out(Object.assign({
      unlockShown: !(await hidden('#unlock')),
      formShown: !(await hidden('#main')),
      pageText: await page.evaluate(() => document.body.innerText),
      msg: await text('#msg'),
      hashAfter: await page.evaluate(() => location.hash),
    }, extra));
    const v = values ? JSON.parse(values) : {};
    const typeUnlock = async (code) => { await page.fill('#unlock-code', code); await page.click('#unlock-go'); };
    if (action === 'locked') {
      // While the page is locked it must not send anything anywhere: no request at all may leave it, whatever the
      // person does here. Count every request the page makes from now on (the link was already read).
      const sent = [];
      page.on('request', (r) => { if (!r.url().startsWith('file:') && !r.url().startsWith('data:')) sent.push(r.method() + ' ' + r.url()); });
      await page.fill('#unlock-code', '00000000');
      await page.click('#unlock-go'); // a wrong code: the page works on it, and still sends nothing
      await page.waitForTimeout(1500);
      await view({ requestsWhileLocked: sent });
      await browser.close();
      return;
    }
    if (action === 'unlock-expect-refused') {
      await typeUnlock(v.unlock);
      await page.waitForTimeout(400);
      await view(); await browser.close(); return;
    }
    if (action === 'unlock-submit-expect-fail') {
      await typeUnlock(v.unlock);
      await page.waitForFunction(() => /could not be unlocked/.test(document.getElementById('msg').textContent), null, { timeout: 15000 });
      await view(); await browser.close(); return;
    }
    if (action === 'unlock-wrong-then-right') {
      await typeUnlock(v.wrong);
      await page.waitForFunction(() => /could not be unlocked/.test(document.getElementById('msg').textContent), null, { timeout: 15000 });
      const failedMsg = await text('#msg');
      await typeUnlock(v.right);
      await page.waitForSelector('#main:not([hidden])', { timeout: 15000 });
      await view({ msg: failedMsg }); await browser.close(); return;
    }
    // unlock-submit: unlock, then fill the form and submit as usual
    await typeUnlock(v.unlock);
    await page.waitForSelector('#main:not([hidden])', { timeout: 15000 });
    await page.check('#verified');
    for (const [k, val] of Object.entries(v)) {
      if (k === 'unlock') continue;
      await page.fill(k === 'factor' ? '#f-seal-factor' : '#f-' + k, val);
    }
    await page.click('#submit');
    await page.waitForFunction(() => {
      const m = document.getElementById('msg');
      return m.classList.contains('bad') || /Done|failed|Rejected|Another step|refused|Stopped/.test(m.textContent);
    }, null, { timeout: 15000 });
    await view({ title: await page.title(), unlockLeft: await page.$eval('#unlock-code', (e) => e.value) });
    await browser.close();
    return;
  }

  if (action === 'derive-link') {
    await page.waitForSelector('#unlock:not([hidden])', { timeout: 10000 });
    const v = JSON.parse(values);
    const derived = await page.evaluate(([code, fpr, mode, round]) => window.__linkSelfCheck(code, fpr, mode, round), [v.code, v.fingerprint, v.mode, v.round]);
    out({ derived });
    await browser.close();
    return;
  }

  if (action === 'derive') {
    await page.waitForSelector('#main:not([hidden])', { timeout: 10000 });
    const v = JSON.parse(values);
    const derived = await page.evaluate(([pw, f, site, mode, round]) => window.__sealSelfCheck(pw, f, site, mode, round), [v.password, v.factor, v.site, v.mode, v.round]);
    out({ derived });
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
    bodyText: await page.evaluate(() => document.body.innerText),
    fieldLabels: await page.$$eval('#fields label', (els) => els.map((e) => e.textContent)),
    fieldTypes: await page.$$eval('#fields input:not(#f-seal-factor)', (els) => els.map((e) => e.type)),
    hashAfter: await page.evaluate(() => location.hash),
    submitDisabledBefore: await page.$eval('#submit', (e) => e.disabled),
    autocomplete: await page.$$eval('#fields input:not(#f-seal-factor)', (els) => els.map((e) => e.autocomplete)),
    factorShown: (await page.$('#f-seal-factor')) !== null,
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
    for (const [k, v] of Object.entries(vals)) await page.fill(k === 'factor' ? '#f-seal-factor' : '#f-' + k, v);
    await page.click('#submit');
  } else if (action === 'reject') {
    await page.click('#reject');
    if (reason) await page.fill('#reason', reason);
    await page.click('#reject');
  }
  // a message of class "bad" is a final answer too: the page refused something before sending (a missing or malformed
  // field), so there is nothing more to wait for
  await page.waitForFunction(() => {
    const m = document.getElementById('msg');
    return m.classList.contains('bad') || /Done|failed|Rejected|Another step|refused|Stopped/.test(m.textContent);
  }, null, { timeout: 15000 });
  state.msg = await text('#msg');
  state.reasonHiddenAfter = await hidden('#reject-box');
  out(state);
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
