package mcpserver

import (
	"testing"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/vault"
)

// testVault returns an initialized, unlocked vault with cheap key derivation, at cfg.Vault.Dir.
func testVault(t testing.TB, cfg *config.Config) *vault.Vault {
	t.Helper()
	v := vault.NewWithCost(cfg.Vault.Dir, 1, 8, 1)
	if err := v.Init("correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	return v
}
