// Package config loads ~/.config/login/config.yaml with environment overrides.
package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	DingTalk DingTalk `yaml:"dingtalk"`
	Tunnel   Tunnel   `yaml:"tunnel"`
	Keys     Keys     `yaml:"keys"`
	Web      Web      `yaml:"web"`
	Sessions Sessions `yaml:"sessions"`
	Archery  Archery  `yaml:"archery"`
}

type DingTalk struct {
	Webhook string   `yaml:"webhook"`
	Secret  string   `yaml:"secret"`
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

type Sessions struct {
	Persist bool `yaml:"persist"`
}

type Archery struct {
	AllowDDL    *bool         `yaml:"allow_ddl"`
	WaitTimeout time.Duration `yaml:"wait_timeout"`
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
	c := &Config{}
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := yaml.Unmarshal(b, c); err != nil {
			return nil, err
		}
	case !errors.Is(err, os.ErrNotExist):
		return nil, err
	}
	c.applyEnv()
	c.applyDefaults(filepath.Dir(path))
	return c, nil
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
	if c.Web.PageURL == "" {
		c.Web.PageURL = "https://leafai.github.io/login/v0.1.0/"
	}
	if c.Web.TTL == 0 {
		c.Web.TTL = 10 * time.Minute
	}
	if c.Archery.WaitTimeout == 0 {
		c.Archery.WaitTimeout = 30 * time.Minute
	}
}
