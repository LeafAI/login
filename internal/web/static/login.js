'use strict';
// Trusted static login page. Everything it needs (mode, key, API URL) comes from the URL fragment
// that was delivered over DingTalk. Nothing fetched from the tunnel decides what is rendered.
(function () {
  const $ = (id) => document.getElementById(id);
  const MODES = {
    login: { label: 'Sign in', fields: [
      { name: 'username', label: 'Username', secret: false, type: 'text', ac: 'username' },
      { name: 'password', label: 'Password', secret: true, type: 'password', ac: 'current-password' }] },
    totp: { label: 'Two-factor code', fields: [
      { name: 'code', label: 'One-time code', secret: false, type: 'text', ac: 'one-time-code', numeric: true }] },
  };
  const FIELD_NAME = /^[a-z_][a-z0-9_]{0,31}$/;

  let ctx = null; // { site, mode, round, api, key, fpr, fields }
  let busy = false;

  function b64urlToBytes(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function say(text, cls) {
    const m = $('msg');
    m.textContent = text || '';
    m.className = cls || '';
  }
  function spaced(fpr) { return (fpr || '').toUpperCase().replace(/(.{4})/g, '$1 ').trim(); }

  function paramsFrom(hash) {
    return new URLSearchParams(hash.replace(/^#/, ''));
  }

  async function parse(p) {
    if (p.get('v') !== '1') throw new Error('Unsupported or missing link version.');
    const api = p.get('u') || '';
    let apiUrl;
    try { apiUrl = new URL(api); } catch (e) { throw new Error('Bad API address in link.'); }
    if (apiUrl.protocol !== 'https:' && apiUrl.protocol !== 'http:') throw new Error('Bad API address in link.');
    const mode = p.get('mode') || '';
    const round = parseInt(p.get('round') || '', 10);
    if (!/^[a-z0-9_-]{1,32}$/.test(mode) || !(round >= 1)) throw new Error('Bad step in link.');
    let fields;
    if (mode === 'custom') {
      let raw;
      try { raw = JSON.parse(new TextDecoder().decode(b64urlToBytes(p.get('fields') || ''))); }
      catch (e) { throw new Error('Bad field list in link.'); }
      if (!Array.isArray(raw) || raw.length === 0 || raw.length > 8) throw new Error('Bad field list in link.');
      fields = raw.map((f) => {
        if (!f || !FIELD_NAME.test(f.name || '')) throw new Error('Bad field name in link.');
        return { name: f.name, label: String(f.label || f.name).slice(0, 60), secret: !!f.secret,
                 type: f.secret ? 'password' : 'text', ac: 'off' };
      });
    } else if (MODES[mode]) {
      fields = MODES[mode].fields;
    } else {
      throw new Error('Unknown step "' + mode + '".');
    }
    const key = await openpgp.readKey({ binaryKey: b64urlToBytes(p.get('k') || '') });
    const fpr = key.getFingerprint().toUpperCase();
    const expected = (p.get('f') || '').toUpperCase();
    if (expected && expected !== fpr) throw new Error('Key fingerprint does not match the link. Do not continue.');
    return { site: (p.get('site') || '').slice(0, 200), mode, round, api: apiUrl.href.replace(/\/+$/, ''), key, fpr, fields };
  }

  function render() {
    $('paste').hidden = true;
    $('main').hidden = false;
    const label = ctx.mode === 'custom' ? 'Additional information' : MODES[ctx.mode].label;
    $('title').textContent = label + ' - ' + (ctx.site || 'site');
    $('d-site').textContent = ctx.site || '(not given)';
    $('d-mode').textContent = label + ' (step ' + ctx.round + ')';
    $('d-host').textContent = new URL(ctx.api).host;
    $('d-fpr').textContent = spaced(ctx.fpr);
    const box = $('fields');
    box.textContent = '';
    ctx.fields.forEach((f, i) => {
      const l = document.createElement('label');
      l.htmlFor = 'f-' + f.name;
      l.textContent = f.label;
      const inp = document.createElement('input');
      inp.id = 'f-' + f.name;
      inp.name = f.name;
      inp.type = f.type;
      inp.required = true;
      inp.autocomplete = f.ac;
      if (f.numeric) inp.inputMode = 'numeric';
      if (i === 0) setTimeout(() => inp.focus(), 0);
      box.append(l, inp);
    });
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
    const resp = await fetch(submit, { method: 'POST', body: armored, headers: { 'Content-Type': 'text/plain' }, cache: 'no-store', referrerPolicy: 'no-referrer' });
    if (!resp.ok) {
      let detail = '';
      try { detail = (await resp.json()).error || ''; } catch (e) { /* ignore */ }
      throw new Error('Server refused the submission (' + resp.status + (detail ? ': ' + detail : '') + ').');
    }
  }

  async function poll() {
    const statusUrl = ctx.api + '/status';
    for (let i = 0; i < 400; i++) {
      await new Promise((r) => setTimeout(r, 1500));
      let st;
      try { st = await (await fetch(statusUrl, { cache: 'no-store', referrerPolicy: 'no-referrer' })).json(); }
      catch (e) { continue; }
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

  async function run(action) {
    if (busy) return;
    busy = true;
    $('submit').disabled = true;
    $('reject').disabled = true;
    try {
      let fields = {};
      let reason = '';
      if (action === 'submit') {
        ctx.fields.forEach((f) => { fields[f.name] = $('f-' + f.name).value; });
      } else {
        reason = $('reason').value.trim().slice(0, 500);
      }
      say('Encrypting and sending...');
      await send(action, fields, reason);
      $('form').querySelectorAll('input,textarea').forEach((e) => { e.value = ''; e.disabled = true; });
      fields = null;
      say('Sent. Waiting for the result...');
      await poll();
    } catch (e) {
      say(String(e && e.message || e), 'bad');
      busy = false;
      $('submit').disabled = false;
      $('reject').disabled = false;
    }
  }

  async function start(p) {
    try {
      ctx = await parse(p);
      render();
    } catch (e) {
      say(String(e && e.message || e), 'bad');
      $('paste').hidden = false;
    }
  }

  $('form').addEventListener('submit', (ev) => { ev.preventDefault(); run('submit'); });
  $('reject').addEventListener('click', () => {
    const box = $('reject-box');
    if (box.hidden) {
      box.hidden = false;
      $('fields').querySelectorAll('input').forEach((i) => { i.required = false; });
      $('reason').focus();
      $('reject').textContent = 'Confirm reject';
      say('Optionally tell the AI agent why, then press "Confirm reject".');
    } else {
      run('reject');
    }
  });
  $('use-link').addEventListener('click', () => {
    const v = $('link').value.trim();
    const i = v.indexOf('#');
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
