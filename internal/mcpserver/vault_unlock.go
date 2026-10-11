package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/securl/internal/audit"
	"github.com/LeafAI/securl/internal/flow"
	"github.com/LeafAI/securl/internal/keyring"
	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/unlockguard"
	"github.com/LeafAI/securl/internal/vault"
)

// maxUnlockTries is how many passphrases one unlock request lets the person type before it gives up. The guard slows
// the wrong ones down well before that; this only bounds a single request.
const maxUnlockTries = 5

// unlockHost is the placeholder "site" of an unlock flow: it names no real host, so a link or message can never be
// mistaken for a login to one.
const unlockHost = "vault.invalid"

// unlocker is the part of the server that works while the vault is shut. It has its own flow manager, because the
// login flow manager is built from the vault's contents (the TOTP secrets) and so does not exist yet.
type unlocker struct {
	s     *Server
	mgr   *flow.Manager
	guard *unlockguard.Guard
	base  *url.URL
}

func newUnlocker(s *Server) *unlocker {
	base, _ := url.Parse("https://" + unlockHost)
	u := &unlocker{s: s, guard: unlockguard.New(unlockguard.Config{}), base: base}
	u.mgr = flow.NewManager(flow.Config{
		Keys:     keyring.NewMemoryPool(s.cfg.Keys.MaxUses, s.cfg.Keys.MaxAge),
		Notifier: s.notify, Tunnels: s.tunnels, PageURL: s.cfg.Web.PageURL, TTL: s.cfg.Vault.UnlockTTL, Log: s.log,
		OnTunnel: func(f *flow.Flow, provider string, attempts int) {
			s.audit.Record(audit.Event{Event: "tunnel", Site: "vault", Tunnel: provider, Attempts: attempts})
		},
		OnRound: func(f *flow.Flow, mode string, round int) {
			s.audit.Record(audit.Event{Event: "vault_unlock_round", Round: round})
		},
		Purpose: &flow.Purpose{
			Title:   "Vault unlock",
			Heading: "Unlock the securl vault",
			Step:    "vault passphrase",
			Warning: "If you did not ask for the vault to be unlocked, ignore this message: nobody can open it without the passphrase.",
		},
	})
	return u
}

// driver returns the driver that runs one unlock request.
func (u *unlocker) driver() site.Driver { return unlockDriver{u: u} }

// unlockDriver asks the person for the passphrase and opens the vault with it. It lets them try again after a wrong one.
type unlockDriver struct{ u *unlocker }

func (unlockDriver) Name() string                                                       { return "vault" }
func (unlockDriver) Match(*url.URL) bool                                                { return false }
func (unlockDriver) NeedsLogin() bool                                                   { return true }
func (unlockDriver) Probe(context.Context, *url.URL, *site.Session, *http.Client) error { return nil }

func (d unlockDriver) Login(ctx context.Context, _ *url.URL, ask site.Asker, _ *http.Client) (*site.Session, error) {
	u := d.u
	for try := 1; try <= maxUnlockTries; try++ {
		if err := u.guard.Allow(); err != nil {
			u.s.audit.Record(audit.Event{Event: "vault_unlock_rate_limited", Result: err.Error()})
			return nil, err
		}
		creds, err := ask.Ask(ctx, "vault", nil)
		if err != nil {
			return nil, err
		}
		pass := creds["passphrase"]
		err = u.s.UnlockWith(pass)
		creds["passphrase"] = ""
		pass = ""
		switch {
		case err == nil:
			u.guard.Succeeded()
			u.s.audit.Record(audit.Event{Event: "vault_unlock", Result: "ok"})
			return &site.Session{}, nil
		case errors.Is(err, vault.ErrWrongPassphrase):
			u.guard.Failed()
			u.s.audit.Record(audit.Event{Event: "vault_unlock", Result: "wrong_passphrase"})
		default:
			// The passphrase was right but the server could not open (a factor is on and its secret is missing, the
			// vault is damaged): asking again would not help, and the person must hear the real reason.
			u.s.audit.Record(audit.Event{Event: "vault_unlock", Result: "failed"})
			return nil, fmt.Errorf("%w: %v", site.ErrLoginRejected, err)
		}
	}
	return nil, fmt.Errorf("%w: %d wrong passphrases in one request", site.ErrBadCredentials, maxUnlockTries)
}

// vaultStatus reports the vault. It needs no unlock and shows nothing secret.
func (s *Server) vaultStatus(_ context.Context, _ *mcp.CallToolRequest, _ Empty) (any, *ToolError) {
	out := VaultStatusOutput{State: s.vault.State().String()}
	if u := s.unlocker; u != nil {
		st := u.guard.Status()
		out.FailedAttempts = st.Failures
		if st.Limited {
			out.RetryAfterSecs = int(st.RetryAfter.Round(time.Second).Seconds())
		}
		out.UnlockPending = u.pending() != nil
	}
	return out, nil
}

func (u *unlocker) pending() *flow.Flow { return u.mgr.Running(u.base) }

// vaultUnlock asks the person to open the vault, or joins an unlock that is already waiting. It never sees the
// passphrase: the person types it into the page, and only the server process reads it.
func (s *Server) vaultUnlock(ctx context.Context, req *mcp.CallToolRequest, in VaultUnlockInput) (any, *ToolError) {
	switch s.vault.State() {
	case vault.NotInitialized:
		e := errf("vault_not_initialized", false, "there is no vault to unlock")
		e.Hint = unlockHintNone
		return nil, e
	case vault.Unlocked:
		if _, terr := s.gate(); terr != nil {
			return nil, terr
		}
		return VaultUnlockOutput{Status: "unlocked", AlreadyUnlocked: true}, nil
	}
	u := s.unlocker
	if u == nil {
		return nil, errf("internal", false, "remote unlock is not available")
	}
	max := s.maxBlock(in.MaxBlockSeconds)
	// A call that names an unlock it started earlier gets that unlock's outcome, even when it has already ended (the
	// person may have rejected it while the agent was not waiting).
	if in.UnlockID != "" {
		if f := u.mgr.Get(in.UnlockID); f != nil {
			return s.awaitUnlock(ctx, req, f, max)
		}
	}
	f := u.pending()
	if f == nil {
		if err := u.guard.Allow(); err != nil {
			return nil, unlockErr(err)
		}
		reason := clip(in.Reason, maxReasonBytes)
		s.audit.Record(audit.Event{Event: "vault_unlock_requested", Reason: reason})
		f = u.mgr.Start(u.driver(), u.base, reason, s.hc, nil)
	}
	return s.awaitUnlock(ctx, req, f, max)
}

func (s *Server) awaitUnlock(ctx context.Context, req *mcp.CallToolRequest, f *flow.Flow, max time.Duration) (any, *ToolError) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	timer := time.NewTimer(max)
	defer timer.Stop()
	var n float64
	for {
		select {
		case <-f.Done():
			if err := f.Result().Err; err != nil {
				return nil, unlockErr(err)
			}
			if s.vault.State() != vault.Unlocked {
				return nil, errf("internal", true, "the unlock finished but the vault is not open")
			}
			return VaultUnlockOutput{Status: "unlocked"}, nil
		case <-timer.C:
			sn := f.Snapshot()
			return VaultUnlockOutput{Status: "pending", LoginID: f.ID, WaitingFor: "vault passphrase", ExpiresAt: fmtTime(sn.ExpiresAt), NextTool: nextVaultUnlock}, nil
		case <-tick.C:
			s.progress(ctx, req, &n, "waiting for the person to type the vault passphrase (DingTalk link sent)")
		case <-ctx.Done():
			return nil, errf("internal", true, "cancelled: %v", ctx.Err())
		}
	}
}

// unlockErr maps what an unlock can end in to a tool error. None of them carries anything about the passphrase.
func unlockErr(err error) *ToolError {
	var lim *unlockguard.Limited
	var rj *flow.RejectedError
	switch {
	case errors.As(err, &lim):
		e := errf("rate_limited", true, "%v", err)
		e.Hint = "Wrong passphrases were typed. Do not retry in a loop: wait, or ask the user to check the passphrase."
		return e
	case errors.As(err, &rj):
		e := errf("user_rejected", false, "%s", rj.Error())
		e.Hint = "The person declined to unlock the vault. Do not ask again unless the user tells you to."
		return e
	case errors.Is(err, flow.ErrHumanTimeout):
		e := errf("human_timeout", true, "nobody typed the passphrase in time")
		e.Hint = "Ask the user to watch DingTalk, then call " + toolVaultUnlock + " again."
		return e
	case errors.Is(err, flow.ErrNotify):
		return errf("notify_failed", true, "%v", err)
	case errors.Is(err, flow.ErrTunnel):
		return errf("tunnel_unavailable", true, "%v", err)
	case errors.Is(err, site.ErrBadCredentials):
		e := errf("bad_credentials", false, "the passphrase was wrong too many times in one request")
		e.Hint = "Ask the user to check the vault passphrase, then call " + toolVaultUnlock + " again."
		return e
	case errors.Is(err, site.ErrLoginRejected):
		return errf("vault_locked", false, "%v", err)
	}
	return errf("internal", false, "%v", err)
}
