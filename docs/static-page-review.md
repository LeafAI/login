# Review of the static login page

Scope: `internal/web/static/` — `index.html`, `securl.css`, `securl.js` and the vendored `openpgp.min.js`
(OpenPGP.js 6.3.2) — plus how the page is built and deployed (`scripts/build-pages.sh`, `.github/workflows/pages.yml`).
Reviewed by reading every line of the HTML/CSS/JS, then testing each finding in headless Chromium against the real
round API (`internal/web/*_test.go`).

## What the page is for, and what it must guarantee

A human opens it from a DingTalk link, types a credential, and the page encrypts it to the key in that link before
anything leaves the browser. The SSH tunnel provider that carries the ciphertext is untrusted. So the page must:

1. render only what the link says (never what the tunnel says),
2. encrypt only to the key in the link, and only send to the tunnel address in the link,
3. make it hard to be tricked into using an attacker's link, and
4. leak nothing (history, referrer, password managers, other origins).

## Findings and what was done

| # | Severity | Finding | Fix | Test |
|---|----------|---------|-----|------|
| 1 | High | **Link spoofing.** Any link (email, chat, a web page) can name an attacker's key and tunnel; the page, served from a trusted origin, would happily collect an LDAP password for it. The page had no way to tell the human the link did not come from the login bot. | The page shows a **verification code** (last 16 hex digits of the key fingerprint). The DingTalk message shows the same code. **Submit stays disabled until the human ticks "I compared the code".** The fingerprint parameter is now mandatory. Reject needs no tick. | `TestBrowserSubmitNeedsVerification` |
| 2 | High | **Bug: empty credentials could be sent.** Opening the reject box removed the `required` flags for good; pressing Submit afterwards posted empty fields. | Validation is explicit in `run()`; the reject box has a Back button; empty fields are never sent. | `TestBrowserEmptySubmitSendsNothing` |
| 3 | Medium | **Exfiltration surface.** The static CSP had to allow `connect-src https: http:` because the tunnel host is only known from the link. Anything that ever ran on the page could post data anywhere. | After a link is accepted the page **inserts a second CSP** (`connect-src <that one tunnel origin>`). Policies only add up, so from then on only the tunnel is reachable. Mutation-checked: with the lock removed the test fails. | `TestBrowserConnectionsAreLockedToTheTunnel` |
| 4 | Medium | **Password-manager capture.** Fields used `autocomplete="current-password"`/`username`, inviting managers to file site passwords under the Pages origin. | `autocomplete="off"` (OTP keeps `one-time-code`); spellcheck/autocapitalize/autocorrect off. | `TestBrowserLoginSubmit`, `TestBrowserTOTPAndCustom` |
| 5 | Medium | **Lenient link parsing.** `round=1abc` was accepted; API addresses could carry user-info (`https://corp.example@evil/…`), query strings or odd schemes; the fingerprint check was skipped when absent; duplicate field names were allowed. | Everything is validated strictly and refused with a message; the page falls back to the paste box. | `TestBrowserRefusesHostileOrBrokenLinks` (11 cases + duplicate fields) |
| 6 | Medium | **Mixed content.** From an https page an `http:` tunnel address fails obscurely in the browser. | Refused up front with an explanation (still allowed for local-file/http copies of the page). | `TestBrowserHTTPSPageRefusesHTTPTunnel` |
| 7 | Low | `fetch` followed redirects and used default credentials mode. | `credentials: 'omit'`, `redirect: 'error'`. | covered by flow tests |
| 8 | Low | The pasted link (key + tunnel address) stayed in the textarea. | Cleared as soon as it is used. | — |
| 9 | Low | Inline `<style>` forced `style-src 'unsafe-inline'`. | CSS moved to `securl.css`; CSP is now `style-src 'self'`. | all browser tests |
| 10 | Low | The page could be framed by another site. | Refuses to run when framed (a `<meta>` CSP cannot set `frame-ancestors`). | — |
| 11 | Low | Status polling swallowed network errors for up to 10 minutes. | After 8 consecutive failures it says the connection is lost and that the answer may still have been received. | — |
| 12 | Low (a11y) | Errors were not announced; the tab title never changed; captcha `alt` was just "captcha"; no visible focus style; no `noscript` text; **white text on the dark-mode accent (#58a6ff) was ≈2.5:1**. | Errors use `role="alert"`; `document.title` is set; descriptive `alt`; `:focus-visible` outlines; `noscript` notice; dark mode uses dark text on the light accent (≈8.9:1), light mode white on #1a5fd0 (≈5.9:1). Ratios computed by hand, not with an audit tool. | `TestBrowserLoginSubmit` (title) |
| 13 | Info | **Vendored crypto library.** `openpgp.min.js` was 6.1.0 (Jan 2025). | Upgraded to **6.3.2**; the file is byte-identical to the npm release and pinned by SHA-256 in a test (`e19bf4f0…4aa1`). Go↔browser PGP interoperability re-tested. I could not retrieve the release notes, so I cannot say which advisories the intermediate versions fixed. | `TestVendoredOpenPGPIsTheOfficialRelease` + all browser tests |
| 14 | Info | The page could be indexed; favicon 404. | `noindex,nofollow`, `robots.txt` (`Disallow: /`), inline empty favicon, `.nojekyll`. | `TestPagesSiteMatchesTheEmbeddedPage` |
| 15 | Info | **Verifiability of the hosted copy.** | `scripts/build-pages.sh` publishes the files byte-for-byte as embedded in the binary plus `SHA256SUMS`; `securl page` prints the same sums. | `TestPagesSiteMatchesTheEmbeddedPage` |

## Decisions worth knowing

* **No Subresource Integrity.** I tried it. Chromium refuses integrity checks on `file://` resources, so the page
  died in local-copy mode (the mode for people who do not trust the hosted copy). It would also add little: the hashes
  would sit in the same origin's HTML that they protect. Removed; the library is pinned by test instead.
* **No cache-busting query strings.** They would make the hosted `index.html` differ from the embedded one and
  defeat byte-for-byte verification.

## Residual risks (not fixed)

1. **The hosted origin is trusted.** Whoever can push to `master` (or compromise GitHub Pages) can change the page.
   Mitigations: branch protection on `master`, the published `SHA256SUMS`, and the local copy from `securl page`.
2. **The verification code only helps if the human compares it.** The checkbox can be ticked blindly.
3. **Cache skew.** GitHub Pages caches for about 10 minutes, so right after a deploy a browser may combine a new
   `index.html` with an old `securl.js` (or the reverse). Pages change rarely; reload fixes it.
4. **Clickjacking defence is script-based**, because `frame-ancestors` cannot be set from a `<meta>` tag.
5. **Dynamic CSP relies on the browser honouring a `<meta>` CSP inserted at runtime.** Chromium does (tested).
   Firefox and Safari were **not tested**; if one ignores it, the page falls back to the static policy, which is no
   worse than before.
6. **Browser coverage:** only Chromium (headless) was exercised. No Firefox/Safari/mobile run, no screen-reader pass.
7. **Large captcha images** make the DingTalk link several kilobytes long; how DingTalk clients display it was not tested.
8. **Time:** the payload carries the browser's clock and the server rejects more than two minutes of skew; a wrong
   device clock produces an error message from the server, shown on the page.

## How to re-verify

```
go test -race ./internal/web          # needs Node + Playwright + Chromium for the browser tests
scripts/build-pages.sh /tmp/site && (cd /tmp/site && sha256sum -c SHA256SUMS)
securl page /tmp/page                  # prints the same sums as the hosted SHA256SUMS
```
