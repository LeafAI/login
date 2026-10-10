// Package config loads ~/.config/login/config.yaml with environment overrides.
package config

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/LeafAI/login/internal/site/generic"
)

type Config struct {
	DingTalk DingTalk `yaml:"dingtalk"`
	Tunnel   Tunnel   `yaml:"tunnel"`
	Keys     Keys     `yaml:"keys"`
	Web      Web      `yaml:"web"`
	MCP      MCP      `yaml:"mcp"`
	Sessions Sessions `yaml:"sessions"`
	Security Security `yaml:"security"`
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
