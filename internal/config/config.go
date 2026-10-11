// Package config loads ~/.config/login/config.yaml with environment overrides.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/LeafAI/securl/internal/seal"
	"github.com/LeafAI/securl/internal/site/generic"
	"github.com/LeafAI/securl/internal/totp"
)

type Config struct {
	DingTalk DingTalk `yaml:"dingtalk"`
	Tunnel   Tunnel   `yaml:"tunnel"`
	Keys     Keys     `yaml:"keys"`
	Web      Web      `yaml:"web"`
	MCP      MCP      `yaml:"mcp"`
	Sessions Sessions `yaml:"sessions"`
	Security Security `yaml:"security"`
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
}

type Sessions struct {
	// Persist keeps logins in an encrypted file so later MCP server processes can reuse them
	// (default false: sessions live in memory only).
	Persist bool   `yaml:"persist"`
	Dir     string `yaml:"dir"`
}

type Security struct {
	// AllowedHosts, when non-empty, restricts which sites the agent may log in to. Entries are
	// glob patterns matched against "host" and "host:port", e.g. "*.corp.example".
	AllowedHosts []string `yaml:"allowed_hosts"`

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
	SecretFile string        `yaml:"secret_file"` // 0600; created by `login config totp init`
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

// Sources loads the secrets of the factors that are switched on. A factor that is on but whose secret cannot be read
// is an error: starting without it would silently drop the protection the person asked for.
func (s Security) Sources() (link, seal *totp.Source, err error) {
	load := func(name string, t TOTP) (*totp.Source, error) {
		if !t.Enabled {
			return nil, nil
		}
		st, err := totp.ParseSettings(t.Period, t.Digits)
		if err != nil {
			return nil, fmt.Errorf("security.%s: %w", name, err)
		}
		secret, err := totp.LoadSecret(t.SecretFile)
		if err != nil {
			return nil, fmt.Errorf("security.%s is on but its secret cannot be used (run `login config totp init`): %w", name, err)
		}
		return &totp.Source{Secret: secret, Settings: st}, nil
	}
	if link, err = load("link_totp", s.LinkTOTP); err != nil {
		return nil, nil, err
	}
	if seal, err = load("seal_totp", s.SealTOTP); err != nil {
		return nil, nil, err
	}
	return link, seal, nil
}

// Validate checks the settings that depend on one another.
func (c *Config) Validate() error {
	if err := c.Security.Validate(); err != nil {
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

// DefaultPath returns the default config file location.
func DefaultPath() string {
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "login", "config.yaml")
	}
	return "config.yaml"
}

// Load reads path (a missing file is not an error), applies defaults and env overrides.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
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

// ParseStrict reports fields in b that Config does not know (typos); it does not apply defaults.
func ParseStrict(b []byte) error {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&Config{}); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func (c *Config) applyEnv() {
	if v := os.Getenv("LOGIN_DINGTALK_WEBHOOK"); v != "" {
		c.DingTalk.Webhook = v
	}
	if v := os.Getenv("LOGIN_DINGTALK_SECRET"); v != "" {
		c.DingTalk.Secret = v
	}
	if v := os.Getenv("LOGIN_TUNNEL_ORDER"); v != "" {
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
	if c.Web.PageURL == "" {
		c.Web.PageURL = "https://leafai.github.io/login/"
	}
	if c.Web.TTL == 0 {
		c.Web.TTL = 10 * time.Minute
	}
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
