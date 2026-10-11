package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/totp"
	"github.com/LeafAI/securl/internal/vault"
)

func TestDefaults(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Keys.MaxUses != 8 || c.Keys.MaxAge != 24*time.Hour {
		t.Errorf("key limits: %+v", c.Keys)
	}
	if !c.Archery.DDLAllowed() {
		t.Error("DDL should be allowed by default")
	}
	if len(c.Tunnel.Order) == 0 {
		t.Error("tunnel order not defaulted")
	}
}

func TestFileAndEnv(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(p, []byte("archery:\n  allow_ddl: false\nkeys:\n  max_uses: 3\n"), 0o600)
	t.Setenv("SECURL_DINGTALK_WEBHOOK", "https://example/hook")
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Archery.DDLAllowed() {
		t.Error("allow_ddl:false ignored")
	}
	if c.Keys.MaxUses != 3 || c.DingTalk.Webhook != "https://example/hook" {
		t.Errorf("unexpected: %+v", c)
	}
}

// ---- the two TOTP factors ----

func parse(t *testing.T, dir, yaml string) *Config {
	t.Helper()
	c, err := Parse([]byte(yaml), dir)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Off by default: nobody has to register anything to use the gateway.
func TestTOTPFactorsAreOffByDefault(t *testing.T) {
	c := parse(t, "/cfg", "")
	if c.Security.LinkTOTP.On() || c.Security.SealTOTP.On() {
		t.Fatal("a factor is on by default")
	}
	if err := c.Security.Validate(); err != nil {
		t.Fatalf("the defaults must be valid: %v", err)
	}
}

// Defaults of a factor that is switched on: the unlock factor uses 10 minutes (the longest period 1Password supports),
// the sealing factor 30 seconds, both 8 digits. The secrets live in the vault, each under its own name; secret_file only
// names where an older version kept them, so that they can be moved into the vault.
func TestTOTPDefaults(t *testing.T) {
	c := parse(t, "/cfg", "security:\n  link_totp: {enabled: true}\n  seal_totp: {enabled: true}\n")
	if got := c.Security.LinkTOTP; got.Period != 10*time.Minute || got.Digits != 8 || got.SecretFile != "/cfg/totp/link.secret" {
		t.Errorf("link_totp defaults = %+v", got)
	}
	if got := c.Security.SealTOTP; got.Period != 30*time.Second || got.Digits != 8 || got.SecretFile != "/cfg/totp/seal.secret" {
		t.Errorf("seal_totp defaults = %+v", got)
	}
	if c.Security.LinkTOTP.SecretFile == c.Security.SealTOTP.SecretFile {
		t.Fatal("the two factors share a secret file: one leak would open both")
	}
	if LinkSecretName == SealSecretName {
		t.Fatal("the two factors share a vault entry: one leak would open both")
	}
}

func TestTOTPSettingsAreValidated(t *testing.T) {
	for name, y := range map[string]string{
		"period under 30 s":  "security:\n  link_totp: {enabled: true, period: 10s}\n",
		"period over a week": "security:\n  link_totp: {enabled: true, period: 200h}\n",
		"5 digits":           "security:\n  seal_totp: {enabled: true, digits: 5}\n",
		"9 digits":           "security:\n  seal_totp: {enabled: true, digits: 9}\n",
		"same secret file":   "security:\n  link_totp: {enabled: true, secret_file: /x/s}\n  seal_totp: {enabled: true, secret_file: /x/s}\n",
	} {
		c := parse(t, "/cfg", y)
		if err := c.Security.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The link is valid for web.ttl. A period longer than that is fine; a period much shorter than the link's life is
// fine too (candidates cover every window), but more than MaxCandidates windows cannot be covered.
func TestLinkTOTPPeriodMustCoverTheLinkLifetimeWithinTheCandidateLimit(t *testing.T) {
	c := parse(t, "/cfg", "web: {ttl: 10m}\nsecurity:\n  link_totp: {enabled: true, period: 30s}\n")
	if err := c.Validate(); err == nil {
		t.Error("30 s windows over a 10 minute link need 21 candidates, more than the limit: it must be refused")
	}
	c = parse(t, "/cfg", "web: {ttl: 10m}\nsecurity:\n  link_totp: {enabled: true, period: 10m}\n")
	if err := c.Validate(); err != nil {
		t.Errorf("the default must be valid: %v", err)
	}
}

// fakeSecrets is a SecretReader over a map.
type fakeSecrets map[string][]byte

func (f fakeSecrets) Get(name string) ([]byte, error) {
	if b, ok := f[name]; ok {
		return b, nil
	}
	return nil, vault.ErrNoEntry
}

// A secret that is missing, or a vault that is locked, stops the server from starting when the factor is on: carrying
// on would mean the feature the person switched on is silently not working.
func TestSourcesFailClosedWhenASecretIsMissing(t *testing.T) {
	c := parse(t, t.TempDir(), "security:\n  link_totp: {enabled: true}\n")
	if _, _, err := c.Security.Sources(fakeSecrets{}); err == nil {
		t.Fatal("a factor that is on with no secret started anyway")
	}
	// off: no secret needed, no sources
	c = parse(t, t.TempDir(), "")
	if l, s, err := c.Security.Sources(fakeSecrets{}); err != nil || l != nil || s != nil {
		t.Fatalf("with both off: %v %v %v", l, s, err)
	}
}

func TestSourcesFailClosedWhenTheVaultIsLocked(t *testing.T) {
	c := parse(t, t.TempDir(), "security:\n  seal_totp: {enabled: true}\n")
	v := vault.NewWithCost(t.TempDir(), 1, 8, 1)
	if err := v.Init("correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	v.Lock()
	_, _, err := c.Security.Sources(v)
	if err == nil || !errors.Is(err, vault.ErrLocked) {
		t.Fatalf("a locked vault must be reported as such, not as a missing secret: %v", err)
	}
	// the two situations need different remedies (unlock vs. make the secret), so the text must not mix them up
	if strings.Contains(err.Error(), "totp init") {
		t.Errorf("a locked vault is not cured by making a secret; the message must not suggest it: %v", err)
	}
	_, _, err = c.Security.Sources(fakeSecrets{})
	if err == nil || !strings.Contains(err.Error(), "totp init") {
		t.Errorf("a missing secret must say how to make one: %v", err)
	}
}

func TestSourcesRefuseAnUnreadableSecret(t *testing.T) {
	c := parse(t, t.TempDir(), "security:\n  link_totp: {enabled: true}\n")
	for name, val := range map[string][]byte{"empty": {}, "too short": []byte("ABC"), "not base32": []byte("!!!!!!!!!!!!!!!!!!!!!!!!")} {
		if _, _, err := c.Security.Sources(fakeSecrets{LinkSecretName: val}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSourcesLoadWhenTheSecretsExist(t *testing.T) {
	c := parse(t, t.TempDir(), "security:\n  link_totp: {enabled: true}\n  seal_totp: {enabled: true, period: 1m, digits: 6}\n")
	a, _ := totp.NewSecret()
	b, _ := totp.NewSecret()
	l, s, err := c.Security.Sources(fakeSecrets{LinkSecretName: []byte(totp.FormatSecret(a)), SealSecretName: []byte(totp.FormatSecret(b))})
	if err != nil || l == nil || s == nil {
		t.Fatalf("sources: %v %v %v", l, s, err)
	}
	if l.Digits() != 8 || s.Digits() != 6 || l.Settings.Period != 10*time.Minute || s.Settings.Period != time.Minute {
		t.Errorf("settings not applied: %+v %+v", l.Settings, s.Settings)
	}
	if string(l.Secret) != string(a) || string(s.Secret) != string(b) {
		t.Error("each factor must get its own secret: the unlock factor the first, the sealing factor the second")
	}
}

func TestSourcesNeverReadTheLegacyFile(t *testing.T) {
	dir := t.TempDir()
	c := parse(t, dir, "security:\n  link_totp: {enabled: true}\n")
	a, _ := totp.NewSecret()
	if err := totp.SaveSecret(c.Security.LinkTOTP.SecretFile, a); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Security.Sources(fakeSecrets{}); err == nil {
		t.Error("a secret left in a file must not be used: it is not protected by the vault")
	}
}

// The boundary is documented (docs/OPERATING.md says "200 seconds or longer" for a 10 minute link), so it is pinned here:
// if the rule changes, this test fails and the document must change with it.
func TestLinkTOTPShortestPeriodForATenMinuteLink(t *testing.T) {
	check := func(period time.Duration) error {
		c := parse(t, "/cfg", "web: {ttl: 10m}\n")
		c.Security.LinkTOTP = TOTP{Enabled: true, Period: period, Digits: 8, SecretFile: "/x/l"}
		return c.Validate()
	}
	if err := check(200 * time.Second); err != nil {
		t.Errorf("200 s must be accepted: %v", err)
	}
	if err := check(199 * time.Second); err == nil {
		t.Error("199 s must be refused")
	}
	// a longer link needs a longer period, in proportion
	c := parse(t, "/cfg", "web: {ttl: 30m}\n")
	c.Security.LinkTOTP = TOTP{Enabled: true, Period: 200 * time.Second, Digits: 8, SecretFile: "/x/l"}
	if c.Validate() == nil {
		t.Error("a 30 minute link with 200 s windows needs 10 windows and must be refused")
	}
}

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadRejectsUnknownKeysAndSaysWhichOne(t *testing.T) {
	cases := []struct{ name, yaml, key, hint string }{
		{"allowed_hosts typo", "security:\n  allowed_host: [\"*.corp.example\"]\n", "allowed_host", "allowed_hosts"},
		{"link_totp enabled typo", "security:\n  link_totp:\n    enable: true\n", "enable", "enabled"},
		{"allow_ddl typo", "archery:\n  allow_dll: false\n", "allow_dll", "allow_ddl"},
		{"top level typo", "securty:\n  allowed_hosts: [a]\n", "securty", "security"},
		{"limits typo", "limits:\n  per_sit: 1\n", "per_sit", "per_site"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeCfg(t, tc.yaml))
			if err == nil {
				t.Fatal("an unknown key must be an error, not silently ignored")
			}
			for _, want := range []string{tc.key, "line ", tc.hint} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error should mention %q: %v", want, err)
				}
			}
		})
	}
}

func TestLoadAcceptsEveryKeyTheWizardWrites(t *testing.T) {
	full := `dingtalk: {webhook: "https://x", secret: s, keyword: k, at_mobiles: ["1"]}
tunnel: {order: [pinggy], timeout: 1m, providers: [{name: n, command: c, url: u, url_regex: r}]}
keys: {dir: d, max_uses: 2, max_age: 1h}
web: {page_url: "https://p", ttl: 5m}
mcp: {max_block_seconds: 20}
sessions: {persist: true, dir: s}
security: {allowed_hosts: [a], link_totp: {enabled: false, period: 10m, digits: 8, secret_file: f}, seal_totp: {enabled: false}}
audit: {enabled: true, file: a}
limits: {per_site: 1, total: 2, window: 1h, reject_cooldown: 1m}
aliases: {a: "https://b"}
site_options: {gitlab: {login_method: ldap}}
roots: {r: /x}
archery: {allow_ddl: false, wait_timeout: 1m, default_group: g, poll_interval: 1s}
sites: []
`
	if _, err := Load(writeCfg(t, full)); err != nil {
		t.Fatalf("a config using every documented key must load: %v", err)
	}
}

func TestLoadStillAcceptsMissingAndEmptyFiles(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "none.yaml")); err != nil {
		t.Fatalf("missing file: %v", err)
	}
	if _, err := Load(writeCfg(t, "")); err != nil {
		t.Fatalf("empty file: %v", err)
	}
	if _, err := Load(writeCfg(t, "# only a comment\n")); err != nil {
		t.Fatalf("comment-only file: %v", err)
	}
}

func TestLoadDoesNotEchoValuesOfBadKeys(t *testing.T) {
	_, err := Load(writeCfg(t, "dingtalk:\n  secrt: SUPERSECRETVALUE\n"))
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), "SUPERSECRETVALUE") {
		t.Errorf("the error must not echo the value: %v", err)
	}
}

func TestLoadStillReportsOtherYAMLErrors(t *testing.T) {
	if _, err := Load(writeCfg(t, "security: [unclosed\n")); err == nil {
		t.Fatal("broken YAML must still fail")
	}
	if _, err := Load(writeCfg(t, "keys:\n  max_uses: many\n")); err == nil {
		t.Fatal("a wrongly typed value must still fail")
	}
}

func TestUnknownKeyErrorSuggestsOnlyNearbyKeys(t *testing.T) {
	_, err := Load(writeCfg(t, "security:\n  allowed_host: [a]\n"))
	if err == nil || !strings.Contains(err.Error(), `did you mean "allowed_hosts"?`) {
		t.Errorf("a near miss should get a suggestion: %v", err)
	}
	_, err = Load(writeCfg(t, "security:\n  zzzzzzzz: 1\n"))
	if err == nil || strings.Contains(err.Error(), "did you mean") || !strings.Contains(err.Error(), "valid keys:") {
		t.Errorf("an unrelated key should list the valid keys instead of guessing: %v", err)
	}
}

func TestShortKeysGetSuggestionsToo(t *testing.T) {
	_, err := Load(writeCfg(t, "security:\n  link_totp:\n    enable: true\n"))
	if err == nil || !strings.Contains(err.Error(), `did you mean "enabled"?`) {
		t.Errorf("a short key one letter off should get a suggestion: %v", err)
	}
}

func TestVaultDefaults(t *testing.T) {
	c := parse(t, "/cfg", "")
	if c.Vault.Dir != "/cfg/vault" {
		t.Errorf("the vault sits next to the config: %q", c.Vault.Dir)
	}
	if c.Vault.IdleLock != 0 {
		t.Errorf("auto-lock is opt-in: %v", c.Vault.IdleLock)
	}
	if c.Vault.UnlockTTL != 10*time.Minute {
		t.Errorf("unlock link lifetime: %v", c.Vault.UnlockTTL)
	}
}

func TestVaultSettingsLoadAndOldSessionKeysStillLoad(t *testing.T) {
	c := parse(t, "/cfg", "vault: {dir: /v, idle_lock: 30m, unlock_ttl: 5m}\nsessions: {persist: true, dir: /old}\n")
	if c.Vault.Dir != "/v" || c.Vault.IdleLock != 30*time.Minute || c.Vault.UnlockTTL != 5*time.Minute {
		t.Errorf("%+v", c.Vault)
	}
	if _, err := Load(writeCfg(t, "sessions: {persist: true, dir: /old}\n")); err != nil {
		t.Errorf("a config written for an earlier version must still load: %v", err)
	}
	if _, err := Load(writeCfg(t, "vault:\n  idle_lok: 1m\n")); err == nil {
		t.Error("a typo in a vault key must be refused like any other")
	}
}

func TestEnvironmentOverridesTheFile(t *testing.T) {
	t.Setenv("SECURL_DINGTALK_WEBHOOK", "https://env/hook")
	t.Setenv("SECURL_DINGTALK_SECRET", "env-secret")
	t.Setenv("SECURL_TUNNEL_ORDER", "serveo,pinggy")
	c := parse(t, "/cfg", "dingtalk: {webhook: \"https://file/hook\", secret: file-secret}\ntunnel: {order: [tunnl]}\n")
	if c.DingTalk.Webhook != "https://env/hook" || c.DingTalk.Secret != "env-secret" {
		t.Errorf("%+v", c.DingTalk)
	}
	if len(c.Tunnel.Order) != 2 || c.Tunnel.Order[0] != "serveo" {
		t.Errorf("%v", c.Tunnel.Order)
	}
}

func TestAnEmptyVariableIsNotSet(t *testing.T) {
	t.Setenv("SECURL_DINGTALK_WEBHOOK", "")
	if c := parse(t, "/cfg", "dingtalk: {webhook: \"https://file/hook\"}\n"); c.DingTalk.Webhook != "https://file/hook" {
		t.Errorf("an empty variable must not blank the file's value: %q", c.DingTalk.Webhook)
	}
}

// The old names are gone, and stay gone: a variable from the previous name is not read.
func TestTheOldNamesAreNotRead(t *testing.T) {
	t.Setenv("LOGIN_DINGTALK_WEBHOOK", "https://old/hook")
	t.Setenv("LOGIN_DINGTALK_SECRET", "old")
	t.Setenv("LOGIN_TUNNEL_ORDER", "tunnl")
	c := parse(t, "/cfg", "")
	if c.DingTalk.Webhook != "" || c.DingTalk.Secret != "" || len(c.Tunnel.Order) == 1 && c.Tunnel.Order[0] == "tunnl" {
		t.Errorf("%+v %v", c.DingTalk, c.Tunnel.Order)
	}
}

func TestDefaultPathIsUnderSecurl(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("AppData", filepath.Join(home, "AppData"))
	d, err := os.UserConfigDir()
	if err != nil {
		t.Skip("no user config dir")
	}
	if got := DefaultPath(); got != filepath.Join(d, "securl", "config.yaml") {
		t.Errorf("%s", got)
	}
}
