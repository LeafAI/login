// Package config loads ~/.config/securl/config.yaml with environment overrides.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/LeafAI/securl/internal/seal"
	"github.com/LeafAI/securl/internal/site/generic"
	"github.com/LeafAI/securl/internal/totp"
	"github.com/LeafAI/securl/internal/vault"
)

type Config struct {
	DingTalk DingTalk `yaml:"dingtalk"`
	Tunnel   Tunnel   `yaml:"tunnel"`
	Keys     Keys     `yaml:"keys"`
	Web      Web      `yaml:"web"`
	MCP      MCP      `yaml:"mcp"`
	Sessions Sessions `yaml:"sessions"`
	Security Security `yaml:"security"`
	Vault    Vault    `yaml:"vault"`
	Audit    Audit    `yaml:"audit"`
	Limits   Limits   `yaml:"limits"`
	// Aliases maps a hostname (or host:port) to a site driver name, for sites whose hostname does not
	// hint at the product, e.g. "es.corp.example": kibana.
	Aliases map[string]string `yaml:"aliases"`
	// SiteOptions passes driver-specific settings by driver name, e.g. kubesphere: {identity_provider: ldap}.
	SiteOptions map[string]map[string]string `yaml:"site_options"`
	// Roots maps a hostname (or host:port) to the full base URL of a site served under a path prefix,
	// e.g. "elk.corp.example": "https://elk.corp.example/kibana".
	Roots   map[string]string `yaml:"roots"`
	Archery Archery           `yaml:"archery"`
	// Sites defines extra websites with the declarative generic driver.
	Sites []generic.Spec `yaml:"sites"`
	// Databases lists the PostgreSQL and MySQL databases an agent may run SQL against (non-production only).
	Databases []Database `yaml:"databases"`
}

// Vault configures the encrypted store that holds every secret login keeps (logged-in sessions, TOTP secrets). It is
// locked whenever the process starts and opens for the vault passphrase.
type Vault struct {
	// Dir holds the vault files (default: "vault" next to the config file).
	Dir string `yaml:"dir"`
	// IdleLock locks the vault again after this long without use (default 0: it stays open until the process ends).
	IdleLock time.Duration `yaml:"idle_lock"`
	// UnlockTTL is how long the DingTalk link that unlocks the vault stays valid (default 10 minutes).
	UnlockTTL time.Duration `yaml:"unlock_ttl"`
}

// Sessions is kept so that existing config files still load. Logins are always stored in the vault now: a session
// is a credential, and credentials live nowhere else.
type Sessions struct {
	// Persist is ignored: sessions are always kept in the vault.
	Persist bool `yaml:"persist"`
	// Dir is ignored; it only names where an older version kept sessions, so that they can be moved into the vault.
	Dir string `yaml:"dir"`
}

type Security struct {
	// AllowedHosts, when non-empty, restricts which sites the agent may log in to. Entries are
	// glob patterns matched against "host" and "host:port", e.g. "*.corp.example".
	AllowedHosts []string `yaml:"allowed_hosts"`
	// AllowLocalAddresses lets the agent reach this machine's own addresses (loopback, link-local, the cloud
	// metadata endpoint). Off by default: an agent-chosen URL must not become a way to probe local services.
	AllowLocalAddresses bool `yaml:"allow_local_addresses"`
	// AllowArcheryRequests lets the request tool talk to Archery. Off by default: Archery has its own tools, where a
	// change waits for a person's approval, is checked for DDL, notifies the approvers and counts against the limits.
	// Through the request tool an agent could post or approve a workflow itself and skip all of that.
	AllowArcheryRequests bool `yaml:"allow_archery_requests"`

	// LinkTOTP is the unlock factor, a long-period TOTP: with it on, the site, the tunnel address and the one-shot
	// password are encrypted in the DingTalk link and the person types its code in the page to read them. The default
	// period is 10 minutes, the longest period that 1Password supports.
	LinkTOTP TOTP `yaml:"link_totp"`
	// SealTOTP is the sealing factor, a 30 second TOTP: the page seals what the person types with its code before
	// anything leaves the browser, and the server opens it with the code it computes itself.
	SealTOTP TOTP `yaml:"seal_totp"`
}

// TOTP configures one time-based code factor. Each factor has its own secret file, so one leak does not open both.
type TOTP struct {
	Enabled    bool          `yaml:"enabled"`
	Period     time.Duration `yaml:"period"`
	Digits     int           `yaml:"digits"`
	SecretFile string        `yaml:"secret_file"` // where an older version kept the secret; only read to move it into the vault
}

// On reports whether the factor is switched on.
func (t TOTP) On() bool { return t.Enabled }

// Validate checks both factors.
func (s Security) Validate() error {
	for name, t := range map[string]TOTP{"link_totp": s.LinkTOTP, "seal_totp": s.SealTOTP} {
		if !t.Enabled {
			continue
		}
		if _, err := totp.ParseSettings(t.Period, t.Digits); err != nil {
			return fmt.Errorf("security.%s: %w", name, err)
		}
	}
	if s.LinkTOTP.Enabled && s.SealTOTP.Enabled && filepath.Clean(s.LinkTOTP.SecretFile) == filepath.Clean(s.SealTOTP.SecretFile) {
		return fmt.Errorf("security: link_totp and seal_totp use the same secret file %s; give each its own, so that one leak does not open both", s.LinkTOTP.SecretFile)
	}
	return nil
}

// The vault entries that hold the two factors' secrets.
const (
	LinkSecretName = "totp/link"
	SealSecretName = "totp/seal"
)

// SecretReader is where the factors' secrets are read from: the vault.
type SecretReader interface {
	Get(name string) ([]byte, error)
}

// Sources loads the secrets of the factors that are switched on from the vault. A factor that is on but whose secret
// cannot be read (it is missing, unreadable, or the vault is locked) is an error: starting without it would silently drop
// the protection the person asked for. A secret left in the legacy secret_file is never used; it is not protected by the
// vault, and `securl vault init` moves it in.
func (s Security) Sources(secrets SecretReader) (link, seal *totp.Source, err error) {
	load := func(name, entry string, t TOTP) (*totp.Source, error) {
		if !t.Enabled {
			return nil, nil
		}
		st, err := totp.ParseSettings(t.Period, t.Digits)
		if err != nil {
			return nil, fmt.Errorf("security.%s: %w", name, err)
		}
		raw, err := secrets.Get(entry)
		if err != nil {
			if errors.Is(err, vault.ErrLocked) || errors.Is(err, vault.ErrNotInitialized) {
				return nil, fmt.Errorf("security.%s is on but its secret cannot be read: %w", name, err)
			}
			return nil, fmt.Errorf("security.%s is on but its secret is not in the vault (run `securl config totp init`): %w", name, err)
		}
		secret, err := totp.ParseSecret(string(raw))
		if err != nil {
			return nil, fmt.Errorf("security.%s is on but its secret in the vault is unusable: %w", name, err)
		}
		return &totp.Source{Secret: secret, Settings: st}, nil
	}
	if link, err = load("link_totp", LinkSecretName, s.LinkTOTP); err != nil {
		return nil, nil, err
	}
	if seal, err = load("seal_totp", SealSecretName, s.SealTOTP); err != nil {
		return nil, nil, err
	}
	return link, seal, nil
}

// Validate checks the settings that depend on one another.
func (c *Config) Validate() error {
	if err := c.Security.Validate(); err != nil {
		return err
	}
	if err := validateDatabases(c.Databases); err != nil {
		return err
	}
	if t := c.Security.LinkTOTP; t.Enabled {
		windows := int((c.Web.TTL+t.Period-1)/t.Period) + 1 // every window the link's life can touch
		if windows > totp.MaxCandidates || windows > seal.MaxLinkSlots {
			return fmt.Errorf("security.link_totp: a %s period over a link that lives %s touches %d windows, more than the %d the link can carry; use a longer period", t.Period, c.Web.TTL, windows, min(totp.MaxCandidates, seal.MaxLinkSlots))
		}
	}
	return nil
}

// Audit controls the append-only activity log (JSON lines, metadata only, no secrets).
type Audit struct {
	// Enabled is on by default; set it to false to turn the log off.
	Enabled *bool  `yaml:"enabled"`
	File    string `yaml:"file"`
}

// On reports whether auditing is enabled (default true).
func (a Audit) On() bool { return a.Enabled == nil || *a.Enabled }

// Limits protects people from being flooded with login requests by an agent. Only requests that
// reach a human count; a cached session never does. A negative value switches a rule off.
type Limits struct {
	PerSite        int           `yaml:"per_site"`        // requests to humans per site per window (default 6)
	Total          int           `yaml:"total"`           // requests to humans overall per window (default 20)
	Window         time.Duration `yaml:"window"`          // default 1h
	RejectCooldown time.Duration `yaml:"reject_cooldown"` // refuse a site after the human rejected it (default 10m)
}

type MCP struct {
	// MaxBlockSeconds is how long blocking tools wait before returning a "pending" result.
	MaxBlockSeconds int `yaml:"max_block_seconds"`
}

type DingTalk struct {
	Webhook string   `yaml:"webhook"`
	Secret  string   `yaml:"secret"`
	Keyword string   `yaml:"keyword"` // required keyword of the robot's security settings, if any
	Mobiles []string `yaml:"at_mobiles"`
}

type Tunnel struct {
	Order   []string         `yaml:"order"`
	Timeout time.Duration    `yaml:"timeout"`
	Custom  []CustomProvider `yaml:"providers"`
}

type CustomProvider struct {
	Name     string `yaml:"name"`
	Command  string `yaml:"command"`
	URL      string `yaml:"url"`
	URLRegex string `yaml:"url_regex"`
}

type Keys struct {
	Dir     string        `yaml:"dir"`
	MaxUses int           `yaml:"max_uses"`
	MaxAge  time.Duration `yaml:"max_age"`
}

type Web struct {
	PageURL string        `yaml:"page_url"`
	TTL     time.Duration `yaml:"ttl"`
}

type Archery struct {
	AllowDDL     *bool         `yaml:"allow_ddl"`
	WaitTimeout  time.Duration `yaml:"wait_timeout"`  // default approval timeout
	DefaultGroup string        `yaml:"default_group"` // resource group used when the tool call gives none
	PollInterval time.Duration `yaml:"poll_interval"`
}

// DDLAllowed reports whether DDL statements may be submitted (default true).
func (a Archery) DDLAllowed() bool { return a.AllowDDL == nil || *a.AllowDDL }

// appName is the name of the program, and of its directory under the user's config directory.
const appName = "securl"

// DefaultPath returns the default config file location.
func DefaultPath() string {
	d, err := os.UserConfigDir()
	if err != nil {
		return "config.yaml"
	}
	return filepath.Join(d, appName, "config.yaml")
}

// Load reads path (a missing file is not an error), rejects unknown keys, applies defaults and env overrides.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := ParseStrict(b); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return Parse(b, filepath.Dir(path))
}

// Parse decodes YAML text (empty is fine), applies env overrides and defaults; dir is where relative
// defaults (keys/, sessions/) live.
func Parse(b []byte, dir string) (*Config, error) {
	c := &Config{}
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, err
	}
	c.applyEnv()
	c.applyDefaults(dir)
	return c, nil
}

// The environment variables that override the file.
const (
	envWebhook     = "SECURL_DINGTALK_WEBHOOK"
	envSecret      = "SECURL_DINGTALK_SECRET"
	envTunnelOrder = "SECURL_TUNNEL_ORDER"
)

func (c *Config) applyEnv() {
	if v := os.Getenv(envWebhook); v != "" {
		c.DingTalk.Webhook = v
	}
	if v := os.Getenv(envSecret); v != "" {
		c.DingTalk.Secret = v
	}
	if v := os.Getenv(envTunnelOrder); v != "" {
		c.Tunnel.Order = strings.Split(v, ",")
	}
}

func (t *TOTP) applyDefaults(period time.Duration, secretFile string) {
	if t.Period == 0 {
		t.Period = period
	}
	if t.Digits == 0 {
		t.Digits = 8
	}
	if t.SecretFile == "" {
		t.SecretFile = secretFile
	}
}

func (c *Config) applyDefaults(dir string) {
	if len(c.Tunnel.Order) == 0 {
		c.Tunnel.Order = []string{"pinggy", "localhost.run", "serveo", "tunnl"}
	}
	if c.Tunnel.Timeout == 0 {
		c.Tunnel.Timeout = 20 * time.Second
	}
	if c.Keys.Dir == "" {
		c.Keys.Dir = filepath.Join(dir, "keys")
	}
	if c.Keys.MaxUses == 0 {
		c.Keys.MaxUses = 8
	}
	if c.Keys.MaxAge == 0 {
		c.Keys.MaxAge = 24 * time.Hour
	}
	if c.Sessions.Dir == "" {
		c.Sessions.Dir = filepath.Join(dir, "sessions")
	}
	if c.Vault.Dir == "" {
		c.Vault.Dir = filepath.Join(dir, "vault")
	}
	if c.Vault.UnlockTTL == 0 {
		c.Vault.UnlockTTL = 10 * time.Minute
	}
	if c.Web.PageURL == "" {
		c.Web.PageURL = "https://leafai.github.io/securl/"
	}
	if c.Web.TTL == 0 {
		c.Web.TTL = 10 * time.Minute
	}
	c.Databases = applyDatabaseDefaults(c.Databases)
	c.Security.LinkTOTP.applyDefaults(10*time.Minute, filepath.Join(dir, "totp", "link.secret"))
	c.Security.SealTOTP.applyDefaults(30*time.Second, filepath.Join(dir, "totp", "seal.secret"))
	if c.Audit.File == "" {
		c.Audit.File = filepath.Join(dir, "audit.jsonl")
	}
	if c.Limits.PerSite == 0 {
		c.Limits.PerSite = 6
	}
	if c.Limits.Total == 0 {
		c.Limits.Total = 20
	}
	if c.Limits.Window == 0 {
		c.Limits.Window = time.Hour
	}
	if c.Limits.RejectCooldown == 0 {
		c.Limits.RejectCooldown = 10 * time.Minute
	}
	if c.MCP.MaxBlockSeconds == 0 {
		c.MCP.MaxBlockSeconds = 50
	}
	if c.Archery.PollInterval == 0 {
		c.Archery.PollInterval = 5 * time.Second
	}
	if c.Archery.WaitTimeout == 0 {
		c.Archery.WaitTimeout = 30 * time.Minute
	}
}
