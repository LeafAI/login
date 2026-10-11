package mcpserver

import (
	"context"
	"errors"
	"testing"

	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/unlockguard"
	"github.com/LeafAI/securl/internal/vault"
)

// answers hands out the passphrases one by one, as a person typing them would.
type answers struct {
	list []string
	asks int
}

func (a *answers) Ask(_ context.Context, mode string, fields []site.Field) (site.Credentials, error) {
	// The page fixes the field and its wording for the vault step, so the request names the step and carries no fields.
	if mode != "vault" || len(fields) != 0 {
		return nil, errors.New("the unlock must ask for the vault step and carry no field list: the page owns that form")
	}
	p := "x"
	if a.asks < len(a.list) {
		p = a.list[a.asks]
	}
	a.asks++
	return site.Credentials{"passphrase": p}, nil
}

func login(t *testing.T, g *gateEnv, a *answers) error {
	t.Helper()
	_, err := g.s.unlocker.driver().Login(context.Background(), g.s.unlocker.base, a, nil)
	return err
}

// One request lets the person try a handful of times. The guard usually stops them sooner; with the guard set wide, the
// request's own limit is what ends it.
func TestOneRequestStopsAfterItsOwnLimitOfWrongPassphrases(t *testing.T) {
	g := gateServer(t, "locked", nil)
	g.s.unlocker.guard = unlockguard.New(unlockguard.Config{FreeAttempts: 1000})
	a := &answers{}
	err := login(t, g, a)
	if !errors.Is(err, site.ErrBadCredentials) {
		t.Fatalf("a request of nothing but wrong passphrases ends as bad credentials: %v", err)
	}
	if a.asks != maxUnlockTries {
		t.Errorf("the person is asked exactly %d times, not %d", maxUnlockTries, a.asks)
	}
	if g.v.State() != vault.Locked {
		t.Error("still locked")
	}
}

func TestARightPassphraseOnTheLastTryStillOpens(t *testing.T) {
	g := gateServer(t, "locked", nil)
	g.s.unlocker.guard = unlockguard.New(unlockguard.Config{FreeAttempts: 1000})
	list := make([]string, maxUnlockTries)
	for i := range list {
		list[i] = "wrong wrong wrong wrong"
	}
	list[maxUnlockTries-1] = gatePass
	a := &answers{list: list}
	if err := login(t, g, a); err != nil {
		t.Fatalf("the last allowed try with the right passphrase must work: %v", err)
	}
	if g.v.State() != vault.Unlocked {
		t.Error("open")
	}
	if a.asks != maxUnlockTries {
		t.Errorf("asks: %d", a.asks)
	}
}

func TestARightPassphraseStopsTheAskingAtOnce(t *testing.T) {
	g := gateServer(t, "locked", nil)
	a := &answers{list: []string{gatePass, "never asked for"}}
	if err := login(t, g, a); err != nil {
		t.Fatal(err)
	}
	if a.asks != 1 {
		t.Errorf("once it is open nobody is asked again: %d asks", a.asks)
	}
}

func TestTheGuardIsConsultedBeforeEveryAsk(t *testing.T) {
	g := gateServer(t, "locked", nil)
	g.s.unlocker.guard = unlockguard.New(unlockguard.Config{FreeAttempts: 2})
	a := &answers{}
	err := login(t, g, a)
	var lim *unlockguard.Limited
	if !errors.As(err, &lim) {
		t.Fatalf("the second wrong passphrase starts the penalty, so the third ask is refused: %v", err)
	}
	if a.asks != 2 {
		t.Errorf("two wrong passphrases are asked for, then the guard refuses before a third: %d asks", a.asks)
	}
}
