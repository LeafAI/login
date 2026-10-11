'use strict';
// Trusted static login page. Everything it needs (mode, key, API address) comes from the URL fragment of the
// link delivered over DingTalk; nothing fetched from the tunnel decides what is rendered. User input is first
// sealed with AES-256-GCM under the round's one-shot password from that link, and the sealed value is then
// OpenPGP-encrypted to the key from that link, so only ciphertext leaves the browser. When the link asks for it
// (parameter "t"), a code typed by the person (a long-period TOTP code from their authenticator) is stretched
// (PBKDF2) and mixed into the AES key as well; the code itself is never sent anywhere.
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
    // The vault step asks for the one value that opens everything login keeps. Its wording and its single field are fixed
    // here and never read from the link: a link that could choose what is shown above this input could ask for anything.
    vault: { label: 'Unlock the vault', fixedTitle: true, fields: [
      { name: 'passphrase', label: 'Vault passphrase', type: 'password', ac: 'off' }] },
  };
  const FIELD_NAME = /^[a-z_][a-z0-9_]{0,31}$/;
  const MODE_NAME = /^[a-z0-9_-]{1,32}$/;
  const ROUND = /^[1-9][0-9]{0,3}$/;
  const IMAGE_URL = /^data:image\/(png|jpeg|gif);base64,[A-Za-z0-9+/]+=*$/;
  const LINK_VERSION = '2';
  const SEAL_PREFIX = 'v1.';
  const SEAL_LABEL = 'securl/seal/v1';
  const SEAL_PREFIX_FACTOR = 'v2.';
  const SEAL_LABEL_FACTOR = 'securl/seal/v2';
  const FACTOR_ITERATIONS = 200000; // must equal seal.FactorIterations on the server
  const FACTOR_DIGITS = /^[678]$/;
  const LINK_PREFIX = 'l1.';
  const LINK_LABEL = 'securl/link/v1';
  const LINK_IV = 12;
  const LINK_SLOT = LINK_IV + 32 + 16; // IV + wrapped 32-byte key + GCM tag
  const LINK_MAX_SLOTS = 4;
  const PASSWORD_BYTES = 32;
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

  // parse validates the link strictly: anything unexpected is refused rather than guessed at. The link has a part that
  // is always in the clear (version, step, key, fingerprint: what the person checks before typing anything) and a
  // part that is either in the clear too (a plain link) or encrypted (parameter "e", opened with the unlock code).
  async function parse(p) {
    if (p.get('v') !== LINK_VERSION) throw new Error('Unsupported or missing link version. Ask the AI agent for a new login.');

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
      if (MODES[mode].fixedTitle && p.has('fields')) throw new Error('This step does not take a field list. Do not continue.');
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

    let factorDigits = 0;
    if (p.has('t')) {
      const t = p.get('t');
      if (!FACTOR_DIGITS.test(t)) throw new Error('Bad one-time code length in link.');
      factorDigits = parseInt(t, 10);
    }

    const base = { mode, round, key, fpr, fields, factorDigits };
    const encrypted = p.has('e') || p.has('c');
    if (encrypted) {
      // An encrypted link carries NONE of the secret parameters in the clear: a link that has both could be steering
      // the page to an address the person never unlocked.
      if (!p.has('e') || !p.has('c')) throw new Error('The link is incomplete (encrypted details without their code length).');
      if (p.has('u') || p.has('s') || p.has('site')) throw new Error('The link is inconsistent (details both encrypted and in the clear).');
      if (!FACTOR_DIGITS.test(p.get('c'))) throw new Error('Bad unlock code length in link.');
      const blob = p.get('e');
      if (!blob.startsWith(LINK_PREFIX)) throw new Error('Unsupported encrypted details in link.');
      return Object.assign(base, { locked: true, unlockDigits: parseInt(p.get('c'), 10), blob });
    }
    return Object.assign(base, parseSecret({ site: p.get('site') || '', u: p.get('u') || '', s: p.get('s') || '' }));
  }

  // parseSecret validates the parameters that are hidden in an encrypted link: the site name, the tunnel address and the
  // one-shot password. It is the same check whether they came in the clear or out of the unlocked blob.
  function parseSecret(x) {
    let apiUrl;
    try { apiUrl = new URL(x.u || ''); } catch (e) { throw new Error('Bad API address in link.'); }
    if (apiUrl.username || apiUrl.password || apiUrl.search || apiUrl.hash) throw new Error('Bad API address in link.');
    if (apiUrl.protocol !== 'https:' && apiUrl.protocol !== 'http:') throw new Error('Bad API address in link.');
    // A page served over https cannot talk to plain http (mixed content); say so instead of failing later.
    if (apiUrl.protocol === 'http:' && location.protocol === 'https:') {
      throw new Error('This link points at an http address, which an https page cannot use. Open the page from a local copy (login page) or use an https tunnel.');
    }
    let password;
    try { password = typeof x.s === 'string' ? b64urlToBytes(x.s) : x.s; } catch (e) { password = new Uint8Array(0); }
    if (!password || password.length !== PASSWORD_BYTES) throw new Error('The link is incomplete (no one-time seal password).');
    return { site: String(x.site || '').slice(0, 200), api: apiUrl.href.replace(/\/+$/, ''), origin: apiUrl.origin, password };
  }

  // ---- unlocking an encrypted link ----

  // linkKeys derives, from the unlock code, the key that opens a slot (PBKDF2 then HKDF), bound to the clear part of the
  // link so that a blob cut out of one link does not open in another.
  async function linkKeys(subtle, code, c) {
    const ctxText = c.fpr + '|' + c.mode + '|' + c.round;
    const salt = new Uint8Array(await subtle.digest('SHA-256', textBytes(LINK_LABEL + '|' + ctxText)));
    const base = await subtle.importKey('raw', textBytes(code), 'PBKDF2', false, ['deriveBits']);
    const stretched = new Uint8Array(await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: FACTOR_ITERATIONS }, base, 256));
    const hbase = await subtle.importKey('raw', stretched, 'HKDF', false, ['deriveBits']);
    const hsalt = new Uint8Array(await subtle.digest('SHA-256', textBytes(LINK_LABEL)));
    const slotKey = new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: hsalt, info: textBytes(LINK_LABEL + '|slot|' + ctxText) }, hbase, 256));
    return { stretched, slotKey, ctxText };
  }

  // openLink returns the parameters hidden in the blob, or null if the code does not open it. Every failure is the same
  // null: a wrong code, a damaged blob and a blob from another link cannot be told apart, and the page does not guess.
  async function openLink(blob, code, c) {
    const subtle = await importPassword();
    let raw;
    try { raw = b64urlToBytes(blob.slice(LINK_PREFIX.length)); } catch (e) { return null; }
    if (raw.length < 1) return null;
    const n = raw[0];
    if (n < 1 || n > LINK_MAX_SLOTS || raw.length < 1 + n * LINK_SLOT + LINK_IV + 16) return null;
    const keys = await linkKeys(subtle, code, c);
    const slotKey = await subtle.importKey('raw', keys.slotKey, { name: 'AES-GCM' }, false, ['decrypt']);
    let linkKey = null;
    for (let i = 0; i < n; i++) {
      const slot = raw.slice(1 + i * LINK_SLOT, 1 + (i + 1) * LINK_SLOT);
      try {
        linkKey = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: slot.slice(0, LINK_IV), additionalData: textBytes(LINK_LABEL + '|slot|' + keys.ctxText), tagLength: 128 }, slotKey, slot.slice(LINK_IV)));
        break;
      } catch (e) { /* not this slot's code: try the next */ }
    }
    if (!linkKey) return null;
    const body = raw.slice(1 + n * LINK_SLOT);
    let plain;
    try {
      const bk = await subtle.importKey('raw', linkKey, { name: 'AES-GCM' }, false, ['decrypt']);
      plain = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: body.slice(0, LINK_IV), additionalData: textBytes(LINK_LABEL + '|body|' + keys.ctxText), tagLength: 128 }, bk, body.slice(LINK_IV)));
    } catch (e) { return null; } finally { linkKey.fill(0); }
    try {
      const j = JSON.parse(new TextDecoder().decode(plain));
      return { site: j.site, u: j.u, s: j.s };
    } catch (e) { return null; } finally { plain.fill(0); }
  }

  // Test hook: the keys derived from fixed inputs, so that the byte-exact vectors can be checked in a real browser.
  window.__linkSelfCheck = async (code, fpr, mode, round) => {
    const subtle = await importPassword();
    const k = await linkKeys(subtle, code, { fpr, mode, round });
    return { linkStretched: hex(k.stretched), linkSlotKey: hex(k.slotKey) };
  };

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
    const fixed = ctx.mode !== 'custom' && MODES[ctx.mode].fixedTitle;
    // A fixed step shows no text that came from the link: not even the site name, which an attacker could write a sentence into.
    document.title = fixed ? label : label + ' - ' + (ctx.site || 'Login');
    $('title').textContent = fixed ? label : label + ' - ' + (ctx.site || 'site');
    $('d-site').textContent = fixed ? 'The login vault (everything login keeps)' : (ctx.site || '(not given)');
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
    if (ctx.factorDigits > 0) {
      const l = document.createElement('label');
      l.htmlFor = 'f-seal-factor';
      l.textContent = 'Sealing code (' + ctx.factorDigits + ' digits, from your authenticator)';
      box.append(l);
      const inp = document.createElement('input');
      inp.id = 'f-seal-factor';
      inp.type = 'password';
      inp.autocomplete = 'off';
      inp.inputMode = 'numeric';
      inp.maxLength = ctx.factorDigits;
      inp.spellcheck = false;
      box.append(inp);
    }
    $('verified').focus();
  }

  function randomHex(n) {
    const b = new Uint8Array(n);
    crypto.getRandomValues(b);
    return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  }

  const textBytes = (t) => new TextEncoder().encode(t);

  function bytesToB64url(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  // seal wraps the plaintext in AES-256-GCM under a key derived (HKDF-SHA256) from the round's one-shot password.
  // The key depends on site, step and round, and the additional data also on the nonce, so a sealed value cannot be
  // replayed into another round or site. A fresh random 12-byte IV is used every time. Wire format:
  // "v1." + base64url(IV || ciphertext || tag), exactly what package seal on the server opens.
  async function importPassword() {
    const subtle = (crypto && crypto.subtle) || null;
    if (!subtle) throw new Error('This browser cannot do the extra encryption step (WebCrypto is unavailable). Use a current browser over https or a local copy of the page.');
    return subtle;
  }

  const hex = (bytes) => Array.from(bytes, (x) => x.toString(16).padStart(2, '0')).join('');

  // stretchFactor = PBKDF2-HMAC-SHA256(code, salt = one-shot password, 200000 iterations) -> 32 bytes.
  async function stretchFactor(subtle, password, factor) {
    const base = await subtle.importKey('raw', textBytes(factor), 'PBKDF2', false, ['deriveBits']);
    return new Uint8Array(await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: password, iterations: FACTOR_ITERATIONS }, base, 256));
  }

  // deriveRaw returns the AES key bytes (and the intermediate values) for the given inputs; seal uses it, and so does
  // the page's self-check in the tests, which compares it byte for byte with the server's derivation.
  async function deriveRaw(subtle, password, factor, site, mode, round) {
    const out = {};
    const concat = (a, b) => { const o = new Uint8Array(a.length + b.length); o.set(a, 0); o.set(b, a.length); return o; };
    const hkdf = async (ikm, label) => {
      const base = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
      const salt = new Uint8Array(await subtle.digest('SHA-256', textBytes(label)));
      const info = textBytes(label + '|' + site + '|' + mode + '|' + round);
      return new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, base, 256));
    };
    out.plainKey = await hkdf(password, SEAL_LABEL);
    if (factor) {
      out.stretched = await stretchFactor(subtle, password, factor);
      out.key = await hkdf(concat(password, out.stretched), SEAL_LABEL_FACTOR);
    } else {
      out.key = out.plainKey;
    }
    return out;
  }

  // seal wraps the plaintext in AES-256-GCM under a key derived (HKDF-SHA256) from the round's one-shot password and,
  // when the link asks for it, the person's second-factor code. The key depends on site, step and round, and the
  // additional data also on the nonce, so a sealed value cannot be replayed into another round or site. A fresh
  // random 12-byte IV is used every time. Wire format: prefix + base64url(IV || ciphertext || tag) with prefix "v1."
  // (no factor) or "v2." (with the factor), exactly what package seal on the server opens.
  async function seal(plaintext, nonce, factor) {
    const subtle = await importPassword();
    const derived = await deriveRaw(subtle, ctx.password, factor, ctx.site, ctx.mode, ctx.round);
    const key = await subtle.importKey('raw', derived.key, { name: 'AES-GCM' }, false, ['encrypt']);
    const label = factor ? SEAL_LABEL_FACTOR : SEAL_LABEL;
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const additional = textBytes(label + '|' + ctx.site + '|' + ctx.mode + '|' + ctx.round + '|' + nonce);
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: additional, tagLength: 128 }, key, textBytes(plaintext)));
    const out = new Uint8Array(iv.length + ct.length);
    out.set(iv, 0);
    out.set(ct, iv.length);
    return (factor ? SEAL_PREFIX_FACTOR : SEAL_PREFIX) + bytesToB64url(out);
  }

  // Test hook: the keys derived from fixed inputs, so that the byte-exact vectors can be checked in a real browser.
  window.__sealSelfCheck = async (password, factor, site, mode, round) => {
    const subtle = await importPassword();
    const pw = Uint8Array.from(password.match(/../g).map((h) => parseInt(h, 16)));
    const d = await deriveRaw(subtle, pw, factor, site, mode, round);
    return { stretched: d.stretched ? hex(d.stretched) : '', plainKey: hex(d.plainKey), key: hex(d.key) };
  };

  async function send(action, fields, reason) {
    const nonce = randomHex(16);
    let factor = '';
    if (ctx.factorDigits > 0) {
      factor = ($('f-seal-factor') || { value: '' }).value.trim();
      if (!new RegExp('^[0-9]{' + ctx.factorDigits + '}$').test(factor)) {
        throw new Error('Type the ' + ctx.factorDigits + '-digit sealing code from your authenticator.');
      }
    }
    const payload = JSON.stringify({
      action, fields: fields || {}, reason: reason || '', nonce,
      ts: Math.floor(Date.now() / 1000), mode: ctx.mode, round: ctx.round,
    });
    const envelope = JSON.stringify({ sealed: await seal(payload, nonce, factor), nonce });
    const message = await openpgp.createMessage({ text: envelope });
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
      if (ctx.factorDigits > 0 && !/^[0-9]+$/.test((($('f-seal-factor') || { value: '' }).value || '').trim())) {
        say('Type the ' + ctx.factorDigits + '-digit sealing code from your authenticator.', 'bad');
        $('f-seal-factor').focus();
        return;
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

  // start accepts a link. A plain link goes straight to the form. An encrypted link first shows only the key code (what
  // the person compares with DingTalk) and the unlock box: nothing about the site or the tunnel is shown, and the page
  // may not yet talk to any address, until the right code has been typed.
  async function start(p) {
    try {
      const parsed = await parse(p);
      if (parsed.locked) {
        ctx = parsed;
        showLocked();
        return;
      }
      ctx = parsed;
      lockConnections(ctx.origin);
      render();
    } catch (e) {
      ctx = null;
      $('main').hidden = true;
      $('unlock').hidden = true;
      $('paste').hidden = false;
      say(String((e && e.message) || e), 'bad');
    }
  }

  function showLocked() {
    $('paste').hidden = true;
    $('main').hidden = true;
    $('unlock').hidden = false;
    document.title = 'Unlock - Login';
    $('title').textContent = 'Unlock this login';
    $('u-code').textContent = grouped(ctx.fpr.slice(-16));
    $('u-digits').textContent = String(ctx.unlockDigits);
    $('unlock-code').maxLength = ctx.unlockDigits;
    $('unlock-code').value = '';
    $('unlock-code').focus();
    say('');
  }

  let unlocking = false;
  async function unlock() {
    if (unlocking || !ctx || !ctx.locked) return;
    const code = $('unlock-code').value.trim();
    if (!new RegExp('^[0-9]{' + ctx.unlockDigits + '}$').test(code)) {
      say('Type the ' + ctx.unlockDigits + '-digit unlock code from your authenticator.', 'bad');
      $('unlock-code').focus();
      return;
    }
    unlocking = true;
    $('unlock-go').disabled = true;
    say('Unlocking...');
    try {
      const opened = await openLink(ctx.blob, code, { fpr: ctx.fpr, mode: ctx.mode, round: ctx.round });
      if (!opened) {
        // One message for every failure: a wrong code, a damaged blob and another link's blob look the same, and the
        // page does not guess which it is.
        say('The details of this login could not be unlocked. Check the code (it changes every few minutes) and try again, or ask the AI agent for a new login.', 'bad');
        return;
      }
      let secret;
      try { secret = parseSecret(opened); } catch (e) { say(String((e && e.message) || e), 'bad'); return; }
      ctx = Object.assign({}, ctx, secret, { locked: false });
      ctx.blob = '';
      $('unlock-code').value = '';
      $('unlock').hidden = true;
      lockConnections(ctx.origin);
      render();
      say('');
    } finally {
      unlocking = false;
      $('unlock-go').disabled = false;
    }
  }

  $('form').addEventListener('submit', (ev) => { ev.preventDefault(); run('submit'); });
  $('unlock-go').addEventListener('click', () => { unlock(); });
  $('unlock-code').addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); unlock(); } });
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
