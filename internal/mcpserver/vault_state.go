package mcpserver

import (
	"github.com/LeafAI/securl/internal/flow"
	"github.com/LeafAI/securl/internal/keyring"
	"github.com/LeafAI/securl/internal/session"
	"github.com/LeafAI/securl/internal/site/archery"
	"github.com/LeafAI/securl/internal/vault"
)

// openCore builds everything that handles a secret. It needs the vault open, because the TOTP secrets and the stored
// sessions are in it. A factor that is switched on but has no usable secret is an error: opening anyway would hand out
// plain links to people who switched the protection on.
func (s *Server) openCore() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.core != nil {
		return nil
	}
	linkSrc, sealSrc, err := s.cfg.Security.Sources(s.vault)
	if err != nil {
		return err
	}
	c := &core{linkTOTP: linkSrc != nil, sealTOTP: sealSrc != nil,
		keys: keyring.NewMemoryPool(s.cfg.Keys.MaxUses, s.cfg.Keys.MaxAge)}
	var unlock, sealing flow.CodeSource
	if linkSrc != nil {
		unlock = linkSrc
	}
	if sealSrc != nil {
		sealing = sealSrc
	}
	c.cache = session.NewPersistent(session.NewStore(s.vault))
	c.cache.Log = s.log
	c.mgr = flow.NewManager(flow.Config{
		Keys:     c.keys,
		Notifier: s.notify, Tunnels: s.tunnels, PageURL: s.cfg.Web.PageURL, TTL: s.cfg.Web.TTL, Log: s.log,
		Admit: s.admit, OnRound: s.onRound, OnTunnel: s.onTunnel, Unlock: unlock, Seal: sealing,
	})
	c.tracker = archery.NewTracker(s.cfg.Archery.DDLAllowed(), s.cfg.Archery.WaitTimeout)
	c.tracker.Poll = s.cfg.Archery.PollInterval
	s.core = c
	return nil
}

// closeCore drops everything that handles a secret: pending logins and their tunnels are ended, and the transport
// keys are forgotten.
func (s *Server) closeCore() {
	s.mu.Lock()
	c := s.core
	s.core = nil
	s.mu.Unlock()
	if c == nil {
		return
	}
	c.mgr.Close()
	c.keys.Forget()
}

// UnlockWith opens the vault with the passphrase and builds the parts that need it. A failure at any point leaves the
// vault locked: the server is never half open.
func (s *Server) UnlockWith(passphrase string) error {
	if err := s.vault.Unlock(passphrase); err != nil {
		return err
	}
	if err := s.openCore(); err != nil {
		s.vault.Lock()
		return err
	}
	return nil
}

// Lock closes the vault and drops everything that handles a secret.
func (s *Server) Lock() {
	s.closeCore()
	s.vault.Lock()
}

// VaultState reports whether the vault exists and whether it is open.
func (s *Server) VaultState() vault.State { return s.vault.State() }

// gate returns the live core, or the error a tool answers with while the vault is closed. The core is dropped the
// moment the vault is found locked (an idle timeout, or `securl vault lock` from another process of the same user),
// so a tool can never use a credential that the vault no longer guards.
func (s *Server) gate() (*core, *ToolError) {
	switch s.vault.State() {
	case vault.NotInitialized:
		e := errf("vault_not_initialized", false, "the vault has not been set up yet, so there are no credentials to use")
		e.Hint = unlockHintNone
		return nil, e
	case vault.Locked:
		s.closeCore()
		e := errf("vault_locked", true, "the vault is locked: every secret is unavailable until the user unlocks it")
		e.Hint = unlockHintLocked
		return nil, e
	}
	s.mu.Lock()
	c := s.core
	s.mu.Unlock()
	if c == nil { // unlocked by someone else (another path opened the vault): build what is needed
		if err := s.openCore(); err != nil {
			e := errf("vault_locked", false, "the vault is open but cannot be used: %v", err)
			e.Hint = "Ask the user to run `securl doctor`."
			return nil, e
		}
		s.mu.Lock()
		c = s.core
		s.mu.Unlock()
	}
	return c, nil
}
