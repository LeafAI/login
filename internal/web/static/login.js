'use strict';
// Trusted static login page. Everything it needs (mode, key, API address) comes from the URL fragment of the
// link delivered over DingTalk; nothing fetched from the tunnel decides what is rendered. User input is
// OpenPGP-encrypted to the key from that link, and only ciphertext leaves the browser.
(function () {
  const PAGE_VERSION = '2';
  const $ = (id) => document.getElementById(id);

  // Refuse to run inside a frame (a hostile page could otherwise overlay or frame it).
  if (window.top !== window.self) {
    document.body.textContent = 'This page must not be shown inside a frame.';
    return;
  }
  $('ver').textContent = 'v' + PAGE_VERSION;

  const MODES = {
    login: { label: 'Sign in', fields: [
      { name: 'username', label: 'Username', type: 'text', ac: 'off' },
      { name: 'password', label: 'Password', type: 'password', ac: 'off' }] },
    totp: { label: 'Two-factor code', fields: [
      { name: 'code', label: 'One-time code', type: 'text', ac: 'one-time-code', numeric: true }] },
  };
  const FIELD_NAME = /^[a-z_][a-z0-9_]{0,31}$/;
  const MODE_NAME = /^[a-z0-9_-]{1,32}$/;
  const ROUND = /^[1-9][0-9]{0,3}$/;
  const IMAGE_URL = /^data:image\/(png|jpeg|gif);base64,[A-Za-z0-9+/]+=*$/;
  const MAX_FIELDS = 8;
  const MAX_IMAGE = 200000;

  let ctx = null; // { site, mode, round, api, origin, key, fpr, fields }
  let busy = false;

  function b64urlToBytes(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // say shows a message; errors use role=alert so screen readers announce them immediately.
  function say(text, cls) {
    const m = $('msg');
    m.textContent = text || '';
    m.className = cls || '';
    m.setAttribute('role', cls === 'bad' ? 'alert' : 'status');
  }

  function grouped(hex) { return (hex || '').toUpperCase().replace(/(.{4})/g, '$1 ').trim(); }

  function paramsFrom(hash) { return new URLSearchParams(hash.replace(/^#/, '')); }

  // parse validates the link strictly: anything unexpected is refused rather than guessed at.
  async function parse(p) {
    if (p.get('v') !== '1') throw new Error('Unsupported or missing link version.');

    let apiUrl;
    try { apiUrl = new URL(p.get('u') || ''); } catch (e) { throw new Error('Bad API address in link.'); }
    if (apiUrl.username || apiUrl.password || apiUrl.search || apiUrl.hash) throw new Error('Bad API address in link.');
    if (apiUrl.protocol !== 'https:' && apiUrl.protocol !== 'http:') throw new Error('Bad API address in link.');
    // A page served over https cannot talk to plain http (mixed content); say so instead of failing later.
    if (apiUrl.protocol === 'http:' && location.protocol === 'https:') {
      throw new Error('This link points at an http address, which an https page cannot use. Open the page from a local copy (login page) or use an https tunnel.');
    }

    const mode = p.get('mode') || '';
    const roundText = p.get('round') || '';
    if (!MODE_NAME.test(mode) || !ROUND.test(roundText)) throw new Error('Bad step in link.');
    const round = parseInt(roundText, 10);

    let fields;
    if (mode === 'custom') {
      let raw;
      try { raw = JSON.parse(new TextDecoder().decode(b64urlToBytes(p.get('fields') || ''))); }
      catch (e) { throw new Error('Bad field list in link.'); }
      if (!Array.isArray(raw) || raw.length === 0 || raw.length > MAX_FIELDS) throw new Error('Bad field list in link.');
      const seen = new Set();
      fields = raw.map((f) => {
        if (!f || !FIELD_NAME.test(f.name || '') || seen.has(f.name)) throw new Error('Bad field name in link.');
        seen.add(f.name);
        const image = (typeof f.image === 'string' && f.image.length < MAX_IMAGE && IMAGE_URL.test(f.image)) ? f.image : '';
        return { name: f.name, label: String(f.label || f.name).slice(0, 60), type: f.secret ? 'password' : 'text', ac: 'off', image };
      });
    } else if (MODES[mode]) {
      fields = MODES[mode].fields;
    } else {
      throw new Error('Unknown step "' + mode.slice(0, 32) + '".');
    }

    const expected = (p.get('f') || '').toUpperCase();
    if (!/^[0-9A-F]{40,64}$/.test(expected)) throw new Error('The link is incomplete (no key fingerprint).');
    let key;
    try { key = await openpgp.readKey({ binaryKey: b64urlToBytes(p.get('k') || '') }); }
    catch (e) { throw new Error('The public key in the link is not valid.'); }
    const fpr = key.getFingerprint().toUpperCase();
    if (expected !== fpr) throw new Error('Key fingerprint does not match the link. Do not continue.');

    return { site: (p.get('site') || '').slice(0, 200), mode, round, api: apiUrl.href.replace(/\/+$/, ''), origin: apiUrl.origin, key, fpr, fields };
  }

  // lockConnections narrows the page's Content-Security-Policy to the one tunnel origin named in the link.
  // Policies only ever add up, so from here on nothing on this page can send data anywhere else.
  function lockConnections(origin) {
    const m = document.createElement('meta');
    m.httpEquiv = 'Content-Security-Policy';
    m.content = "connect-src " + origin;
    document.head.appendChild(m);
  }

  function render() {
    $('paste').hidden = true;
    $('main').hidden = false;
    const label = ctx.mode === 'custom' ? 'Additional information' : MODES[ctx.mode].label;
    document.title = label + ' - ' + (ctx.site || 'Login');
    $('title').textContent = label + ' - ' + (ctx.site || 'site');
    $('d-site').textContent = ctx.site || '(not given)';
    $('d-mode').textContent = label + ' (step ' + ctx.round + ')';
    $('d-host').textContent = new URL(ctx.api).host;
    $('d-fpr').textContent = grouped(ctx.fpr);
    // The same last 16 hex digits appear in the DingTalk message ("Key").
    $('d-code').textContent = grouped(ctx.fpr.slice(-16));
    $('verified').checked = false;
    $('submit').disabled = true;

    const box = $('fields');
    box.textContent = '';
    ctx.fields.forEach((f) => {
      const l = document.createElement('label');
      l.htmlFor = 'f-' + f.name;
      l.textContent = f.label;
      box.append(l);
      if (f.image) {
        const img = document.createElement('img');
        img.className = 'captcha';
        img.alt = 'Captcha image: enter its answer in the field below';
        img.src = f.image; // validated as a base64 png/jpeg/gif data URL when the link was parsed
        box.append(img);
      }
      const inp = document.createElement('input');
      inp.id = 'f-' + f.name;
      inp.name = f.name;
      inp.type = f.type;
      inp.autocomplete = f.ac; // off: password managers must not file site passwords under this page's origin
      inp.spellcheck = false;
      inp.setAttribute('autocapitalize', 'off');
      inp.setAttribute('autocorrect', 'off');
      if (f.numeric) inp.inputMode = 'numeric';
      box.append(inp);
    });
    $('verified').focus();
  }

  function randomHex(n) {
    const b = new Uint8Array(n);
    crypto.getRandomValues(b);
    return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  }

  async function send(action, fields, reason) {
    const payload = JSON.stringify({
      action, fields: fields || {}, reason: reason || '', nonce: randomHex(16),
      ts: Math.floor(Date.now() / 1000), mode: ctx.mode, round: ctx.round,
    });
    const message = await openpgp.createMessage({ text: payload });
    const armored = await openpgp.encrypt({ message, encryptionKeys: ctx.key, format: 'armored' });
    const submit = ctx.api + '/submit?mode=' + encodeURIComponent(ctx.mode) + '&round=' + ctx.round;
    const resp = await fetch(submit, {
      method: 'POST', body: armored, headers: { 'Content-Type': 'text/plain' },
      cache: 'no-store', referrerPolicy: 'no-referrer', credentials: 'omit', redirect: 'error',
    });
    if (!resp.ok) {
      let detail = '';
      try { detail = String((await resp.json()).error || '').slice(0, 120); } catch (e) { /* ignore */ }
      throw new Error('The login server refused the submission (' + resp.status + (detail ? ': ' + detail : '') + ').');
    }
  }

  const POLL_MS = 1500;
  const POLL_MAX = 400;
  const POLL_MAX_FAILURES = 8;

  async function poll() {
    const statusUrl = ctx.api + '/status';
    let failures = 0;
    for (let i = 0; i < POLL_MAX; i++) {
      await new Promise((r) => setTimeout(r, POLL_MS));
      let st;
      try {
        const resp = await fetch(statusUrl, { cache: 'no-store', referrerPolicy: 'no-referrer', credentials: 'omit', redirect: 'error' });
        st = await resp.json();
        failures = 0;
      } catch (e) {
        if (++failures >= POLL_MAX_FAILURES) {
          say('Lost contact with the login server. Your answer may still have been received; check with the AI agent.', 'bad');
          return;
        }
        continue;
      }
      const text = typeof st.message === 'string' ? st.message.slice(0, 300) : '';
      switch (st.state) {
        case 'done': say('Done. You can close this page.' + (text ? '\n' + text : ''), 'ok'); return;
        case 'failed': say('Login failed.' + (text ? '\n' + text : ''), 'bad'); return;
        case 'rejected': say('Rejected. The AI agent has been told.', 'ok'); return;
        case 'next_round': say('Another step is needed. Check DingTalk for a new link.' + (text ? '\n' + text : ''), 'ok'); return;
        default: say('Working...');
      }
    }
    say('Stopped waiting for a result.', 'bad');
  }

  function setBusy(on) {
    busy = on;
    $('submit').disabled = on || !$('verified').checked;
    $('reject').disabled = on;
    $('reject-cancel').disabled = on;
  }

  function showRejectBox(show) {
    $('reject-box').hidden = !show;
    $('reject-cancel').hidden = !show;
    $('reject').textContent = show ? 'Confirm reject' : 'Reject';
    if (show) {
      $('reason').focus();
      say('Optionally tell the AI agent why, then press "Confirm reject".');
    } else {
      say('');
    }
  }

  async function run(action) {
    if (busy) return;
    let fields = {};
    let reason = '';
    if (action === 'submit') {
      for (const f of ctx.fields) {
        const v = $('f-' + f.name).value;
        if (v === '') {
          say('Please fill in: ' + f.label + '.', 'bad');
          $('f-' + f.name).focus();
          return;
        }
        fields[f.name] = v;
      }
    } else {
      reason = $('reason').value.trim().slice(0, 500);
    }
    setBusy(true);
    try {
      say('Encrypting and sending...');
      await send(action, fields, reason);
      $('form').querySelectorAll('input,textarea').forEach((e) => { e.value = ''; e.disabled = true; });
      fields = null;
      say('Sent. Waiting for the result...');
      await poll();
    } catch (e) {
      say(String((e && e.message) || e), 'bad');
      setBusy(false);
    }
  }

  async function start(p) {
    try {
      ctx = await parse(p);
      lockConnections(ctx.origin);
      render();
    } catch (e) {
      ctx = null;
      $('main').hidden = true;
      $('paste').hidden = false;
      say(String((e && e.message) || e), 'bad');
    }
  }

  $('form').addEventListener('submit', (ev) => { ev.preventDefault(); run('submit'); });
  $('verified').addEventListener('change', () => { $('submit').disabled = busy || !$('verified').checked; });
  $('reject').addEventListener('click', () => {
    if ($('reject-box').hidden) showRejectBox(true); else run('reject');
  });
  $('reject-cancel').addEventListener('click', () => showRejectBox(false));
  $('use-link').addEventListener('click', () => {
    const v = $('link').value.trim();
    const i = v.indexOf('#');
    $('link').value = ''; // the link carries the key and tunnel address: do not leave it in the page
    if (i < 0) { say('That does not look like a login link.', 'bad'); return; }
    say('');
    start(paramsFrom(v.slice(i)));
  });

  if (location.hash.length > 1) {
    const p = paramsFrom(location.hash);
    history.replaceState(null, '', location.pathname + location.search);
    start(p);
  } else {
    $('paste').hidden = false;
  }
})();
