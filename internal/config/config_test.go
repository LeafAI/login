package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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
