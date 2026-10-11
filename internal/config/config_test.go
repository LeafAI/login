package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/totp"
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
	t.Setenv("LOGIN_DINGTALK_WEBHOOK", "https://example/hook")
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
// the sealing factor 30 seconds, both 8 digits, and the secrets live next to the config in their own private files.
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

// A secret file that does not exist, or is exposed, stops the server from starting when the factor is on: carrying on
// would mean the feature the person switched on is silently not working.
func TestSourcesFailClosedWhenASecretIsMissing(t *testing.T) {
	dir := t.TempDir()
	c := parse(t, dir, "security:\n  link_totp: {enabled: true}\n")
	if _, _, err := c.Security.Sources(); err == nil {
		t.Fatal("a factor that is on with no secret file started anyway")
	}
	// off: no secret needed, no sources
	c = parse(t, dir, "")
	if l, s, err := c.Security.Sources(); err != nil || l != nil || s != nil {
		t.Fatalf("with both off: %v %v %v", l, s, err)
	}
}

func TestSourcesLoadWhenTheSecretsExist(t *testing.T) {
	dir := t.TempDir()
	c := parse(t, dir, "security:\n  link_totp: {enabled: true}\n  seal_totp: {enabled: true, period: 1m, digits: 6}\n")
	a, _ := totp.NewSecret()
	b, _ := totp.NewSecret()
	if err := totp.SaveSecret(c.Security.LinkTOTP.SecretFile, a); err != nil {
		t.Fatal(err)
	}
	if err := totp.SaveSecret(c.Security.SealTOTP.SecretFile, b); err != nil {
		t.Fatal(err)
	}
	l, s, err := c.Security.Sources()
	if err != nil || l == nil || s == nil {
		t.Fatalf("sources: %v %v %v", l, s, err)
	}
	if l.Digits() != 8 || s.Digits() != 6 || l.Settings.Period != 10*time.Minute || s.Settings.Period != time.Minute {
		t.Errorf("settings not applied: %+v %+v", l.Settings, s.Settings)
	}
	if string(l.Secret) == string(s.Secret) {
		t.Error("the two sources have the same secret")
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
