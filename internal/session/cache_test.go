package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/vault"
)

// probeDriver accepts sessions whose first token is "good".
type probeDriver struct{}

func (probeDriver) Name() string        { return "sessiontest" }
func (probeDriver) Match(*url.URL) bool { return false }
func (probeDriver) NeedsLogin() bool    { return true }
func (probeDriver) Login(context.Context, *url.URL, site.Asker, *http.Client) (*site.Session, error) {
	return nil, errors.New("unused")
}
func (probeDriver) Probe(_ context.Context, _ *url.URL, s *site.Session, _ *http.Client) error {
	if s.Tokens["t"] != "good" {
		return errors.New("stale")
	}
	return nil
}

func init() { site.Register(probeDriver{}) }

func sample(tok string) *site.Session {
	return &site.Session{
		Cookies: []*http.Cookie{{Name: "sid", Value: "SECRET-COOKIE-VALUE", Path: "/", Secure: true, HttpOnly: true, Expires: time.Now().Add(time.Hour).Truncate(time.Second)}},
		Headers: map[string]string{"Authorization": "Bearer SECRET-BEARER"},
		Tokens:  map[string]string{"t": tok},
	}
}

// fastVault is a vault with cheap key derivation, so that tests stay quick.
func fastVault(t *testing.T, dir string) *vault.Vault {
	t.Helper()
	return vault.NewWithCost(dir, 1, 8, 1)
}

const testPass = "correct horse battery staple"

func openVault(t *testing.T, dir string) *vault.Vault {
	t.Helper()
	v := fastVault(t, dir)
	switch v.State() {
	case vault.NotInitialized:
		if err := v.Init(testPass); err != nil {
			t.Fatal(err)
		}
	default:
		if err := v.Unlock(testPass); err != nil {
			t.Fatal(err)
		}
	}
	return v
}

func TestPersistAcrossProcessesAndEncryption(t *testing.T) {
	dir := t.TempDir()
	u, _ := url.Parse("https://site.example/some/path")
	a := NewPersistent(NewStore(openVault(t, dir)))
	a.Put(u, probeDriver{}, sample("good"))

	// Nothing the session holds, and not even the site it belongs to, may be in any file in the clear.
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, _ := os.ReadFile(p)
		for _, secret := range []string{"SECRET-COOKIE-VALUE", "SECRET-BEARER", "site.example"} {
			if bytes.Contains(raw, []byte(secret)) {
				t.Errorf("plaintext %q found in %s", secret, p)
			}
		}
		return nil
	})
	for _, f := range []string{"sessions.enc", "sessions.key"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			t.Errorf("%s must no longer exist: the key is not stored next to the data any more", f)
		}
	}

	// A different Cache (another process) sees the session, probes it, and gets the cookie details back.
	b := NewPersistent(NewStore(openVault(t, dir)))
	e, ok := b.Get(context.Background(), u, http.DefaultClient)
	if !ok || e.Session.Cookies[0].Value != "SECRET-COOKIE-VALUE" || !e.Session.Cookies[0].Secure || e.Session.Headers["Authorization"] != "Bearer SECRET-BEARER" {
		t.Fatalf("reload failed: %+v ok=%v", e, ok)
	}
	if len(b.List()) != 1 {
		t.Errorf("list = %d", len(b.List()))
	}

	// Deleting in one process removes it for the other.
	if !b.Delete(Key(u)) {
		t.Error("delete reported nothing removed")
	}
	if _, ok := NewPersistent(NewStore(openVault(t, dir))).Get(context.Background(), u, http.DefaultClient); ok {
		t.Error("deleted session still available")
	}
}

func TestStaleSessionDroppedFromStore(t *testing.T) {
	dir := t.TempDir()
	u, _ := url.Parse("https://stale.example")
	NewPersistent(NewStore(openVault(t, dir))).Put(u, probeDriver{}, sample("bad"))
	c := NewPersistent(NewStore(openVault(t, dir)))
	if _, ok := c.Get(context.Background(), u, http.DefaultClient); ok {
		t.Fatal("stale session was returned")
	}
	if n := len(NewStore(openVault(t, dir)).load()); n != 0 {
		t.Errorf("stale session not removed from the store: %d left", n)
	}
}

func TestLockedVaultYieldsNoSessionsAndKeepsThemSafe(t *testing.T) {
	dir := t.TempDir()
	u, _ := url.Parse("https://x.example")
	v := openVault(t, dir)
	c := NewPersistent(NewStore(v))
	c.Put(u, probeDriver{}, sample("good"))
	v.Lock()
	fresh := NewPersistent(NewStore(v))
	if _, ok := fresh.Get(context.Background(), u, http.DefaultClient); ok {
		t.Error("a locked vault must not give out a session")
	}
	if len(fresh.List()) != 0 {
		t.Error("a locked vault lists nothing")
	}
	// Writing while locked must neither panic nor lose what is stored.
	fresh.Put(u, probeDriver{}, sample("other"))
	fresh.Delete(Key(u))
	if err := v.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	if _, ok := NewPersistent(NewStore(v)).Get(context.Background(), u, http.DefaultClient); !ok {
		t.Error("the stored session must survive operations attempted while the vault was locked")
	}
}

func TestCorruptEntryIsSkippedNotFatal(t *testing.T) {
	dir := t.TempDir()
	v := openVault(t, dir)
	u, _ := url.Parse("https://good.example")
	NewPersistent(NewStore(v)).Put(u, probeDriver{}, sample("good"))
	if err := v.Put("session/https://garbage.example", []byte("not json")); err != nil {
		t.Fatal(err)
	}
	st := NewStore(v)
	if n := len(st.load()); n != 1 {
		t.Errorf("one good record and one garbage record: loaded %d, want 1", n)
	}
	if _, ok := NewPersistent(st).Get(context.Background(), u, http.DefaultClient); !ok {
		t.Error("a garbage neighbour must not hide a good session")
	}
}

func TestSessionsLiveUnderTheirOwnPrefix(t *testing.T) {
	v := openVault(t, t.TempDir())
	if err := v.Put("totp/link", []byte("x")); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("https://p.example")
	c := NewPersistent(NewStore(v))
	c.Put(u, probeDriver{}, sample("good"))
	if got := c.Clear(); got != 1 {
		t.Errorf("clear removed %d, want 1", got)
	}
	if _, err := v.Get("totp/link"); err != nil {
		t.Errorf("clearing sessions must not touch other vault entries: %v", err)
	}
}

func TestMemoryOnlyByDefault(t *testing.T) {
	u, _ := url.Parse("https://m.example")
	c := New()
	c.Put(u, probeDriver{}, sample("good"))
	if _, ok := c.Get(context.Background(), u, http.DefaultClient); !ok {
		t.Fatal("memory cache lost the session")
	}
	if c.Clear() != 1 {
		t.Error("clear count")
	}
}

func TestPersistFailureIsLoggedAndTheSessionStillWorksInMemory(t *testing.T) {
	dir := t.TempDir()
	v := openVault(t, dir)
	c := NewPersistent(NewStore(v))
	var logged []string
	c.Log = func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }
	v.Lock()
	u, _ := url.Parse("https://mem.example")
	c.Put(u, probeDriver{}, sample("good"))
	if len(logged) == 0 {
		t.Error("a session that could not be saved must be reported, not dropped silently")
	}
	for _, l := range logged {
		if strings.Contains(l, "SECRET") {
			t.Errorf("a log line leaks a secret: %q", l)
		}
	}
	if _, ok := c.Get(context.Background(), u, http.DefaultClient); !ok {
		t.Error("the in-memory copy must keep working for this process")
	}
	if err := v.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	if _, ok := NewPersistent(NewStore(v)).Get(context.Background(), u, http.DefaultClient); ok {
		t.Error("what could not be saved must not appear in the store later")
	}
}

func TestRecordUnderAnotherNameIsNotTrusted(t *testing.T) {
	v := openVault(t, t.TempDir())
	u, _ := url.Parse("https://real.example")
	NewPersistent(NewStore(v)).Put(u, probeDriver{}, sample("good"))
	raw, _ := v.Get(entryName(Key(u)))
	// the same record filed under another site's name must not be served for that site
	v.Put(entryName("https://other.example"), raw)
	other, _ := url.Parse("https://other.example")
	if _, ok := NewPersistent(NewStore(v)).Get(context.Background(), other, http.DefaultClient); ok {
		t.Error("a record whose base does not match the name it is stored under must be ignored")
	}
}

func TestForgedRecordCannotShadowARealSession(t *testing.T) {
	v := openVault(t, t.TempDir())
	u, _ := url.Parse("https://real.example")
	NewPersistent(NewStore(v)).Put(u, probeDriver{}, sample("good"))
	// A record that claims the real site's base but is filed under another name, and sorts after it.
	forged, _ := json.Marshal(record{Site: "sessiontest", Base: Key(u), Tokens: map[string]string{"t": "bad"}})
	if err := v.Put(entryName("https://zzz.example"), forged); err != nil {
		t.Fatal(err)
	}
	got := NewStore(v).load()[Key(u)]
	if got.Tokens["t"] != "good" {
		t.Errorf("a record filed under another name must not replace the real one: %v", got.Tokens)
	}
}

func TestOnlySessionEntriesAreTreatedAsSessions(t *testing.T) {
	v := openVault(t, t.TempDir())
	// valid record JSON, filed under a name without the session prefix
	rec, _ := json.Marshal(record{Site: "sessiontest", Base: "https://eq.example", Tokens: map[string]string{"t": "good"}})
	if err := v.Put("https://eq.example", rec); err != nil {
		t.Fatal(err)
	}
	if n := len(NewStore(v).load()); n != 0 {
		t.Errorf("an entry outside the session prefix must not be read as a session: %d loaded", n)
	}
	u, _ := url.Parse("https://eq.example")
	c := NewPersistent(NewStore(v))
	c.Delete(Key(u))
	if _, err := v.Get("https://eq.example"); err != nil {
		t.Errorf("deleting a session must not remove entries outside the prefix: %v", err)
	}
}

func TestUpdateThatChangesNothingWritesNothing(t *testing.T) {
	dir := t.TempDir()
	v := openVault(t, dir)
	u, _ := url.Parse("https://quiet.example")
	st := NewStore(v)
	NewPersistent(st).Put(u, probeDriver{}, sample("good"))
	before, _ := os.ReadFile(filepath.Join(dir, "data.enc"))
	if err := st.update(func(map[string]record) {}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "data.enc"))
	if !bytes.Equal(before, after) {
		t.Error("an update that changes nothing must not rewrite the vault (every write costs a re-encryption of everything)")
	}
}

// A proxied request is not a login: probing the site before every request would double the traffic and, for a driver
// whose probe is a real API call, spend the site's rate limit. A session that was validated a moment ago is reused.
type countingDriver struct{ probes *int }

func (countingDriver) Name() string        { return "sessiontest" }
func (countingDriver) Match(*url.URL) bool { return false }
func (countingDriver) NeedsLogin() bool    { return true }
func (countingDriver) Login(context.Context, *url.URL, site.Asker, *http.Client) (*site.Session, error) {
	return nil, errors.New("unused")
}
func (c countingDriver) Probe(context.Context, *url.URL, *site.Session, *http.Client) error {
	*c.probes++
	return nil
}

func TestGetWithinReusesARecentlyValidatedSessionWithoutProbing(t *testing.T) {
	probes := 0
	u, _ := url.Parse("https://fresh.example")
	c := New()
	c.Put(u, countingDriver{&probes}, sample("good")) // Put counts as validated: the login just succeeded
	for i := 0; i < 5; i++ {
		if _, ok := c.GetWithin(context.Background(), u, http.DefaultClient, time.Minute); !ok {
			t.Fatal("the session is fresh")
		}
	}
	if probes != 0 {
		t.Errorf("a fresh session must not be probed again: %d probes", probes)
	}
}

func TestGetWithinProbesASessionThatWasValidatedLongAgo(t *testing.T) {
	probes := 0
	u, _ := url.Parse("https://stale.example")
	c := New()
	c.Put(u, countingDriver{&probes}, sample("good"))
	c.mu.Lock()
	c.m[Key(u)].ValidatedAt = time.Now().Add(-time.Hour)
	c.mu.Unlock()
	if _, ok := c.GetWithin(context.Background(), u, http.DefaultClient, time.Minute); !ok {
		t.Fatal("still valid")
	}
	if probes != 1 {
		t.Errorf("an old validation is renewed: %d probes", probes)
	}
	if _, ok := c.GetWithin(context.Background(), u, http.DefaultClient, time.Minute); !ok || probes != 1 {
		t.Errorf("and then it is fresh again: %d probes", probes)
	}
}

func TestGetWithinDropsASessionThatFailsItsProbe(t *testing.T) {
	u, _ := url.Parse("https://dead.example")
	c := New()
	c.Put(u, probeDriver{}, sample("bad"))
	c.mu.Lock()
	c.m[Key(u)].ValidatedAt = time.Now().Add(-time.Hour)
	c.mu.Unlock()
	if _, ok := c.GetWithin(context.Background(), u, http.DefaultClient, time.Minute); ok {
		t.Error("a session the site no longer accepts must not be handed out")
	}
	if _, ok := c.GetWithin(context.Background(), u, http.DefaultClient, time.Minute); ok {
		t.Error("and it is gone")
	}
}

func TestGetWithinNeverReturnsAnExpiredSession(t *testing.T) {
	probes := 0
	u, _ := url.Parse("https://expired.example")
	c := New()
	s := sample("good")
	s.ExpiresAt = time.Now().Add(-time.Second)
	c.Put(u, countingDriver{&probes}, s)
	if _, ok := c.GetWithin(context.Background(), u, http.DefaultClient, time.Hour); ok {
		t.Error("expiry beats freshness")
	}
}

func TestGetWithinZeroMeansAlwaysProbe(t *testing.T) {
	probes := 0
	u, _ := url.Parse("https://zero.example")
	c := New()
	c.Put(u, countingDriver{&probes}, sample("good"))
	c.GetWithin(context.Background(), u, http.DefaultClient, 0)
	c.GetWithin(context.Background(), u, http.DefaultClient, 0)
	if probes != 2 {
		t.Errorf("%d", probes)
	}
}

func TestUpdateReplacesTheStoredSessionAndKeepsItsIdentity(t *testing.T) {
	dir := t.TempDir()
	u, _ := url.Parse("https://rotate.example")
	c := NewPersistent(NewStore(openVault(t, dir)))
	c.Put(u, probeDriver{}, sample("good"))
	before, _ := c.GetWithin(context.Background(), u, http.DefaultClient, time.Hour)
	next := sample("good")
	next.Cookies = []*http.Cookie{{Name: "sid", Value: "ROTATED-VALUE-123456", Path: "/"}}
	if !c.Update(u, next) {
		t.Fatal("a session that is cached can be updated")
	}
	got, ok := c.GetWithin(context.Background(), u, http.DefaultClient, time.Hour)
	if !ok || got.Session.Cookies[0].Value != "ROTATED-VALUE-123456" {
		t.Fatalf("the update is visible: %+v", got)
	}
	if got.Site != before.Site || got.Driver == nil || !got.ObtainedAt.Equal(before.ObtainedAt) {
		t.Errorf("only the credentials change; the site, the driver and when the login happened stay: %+v", got)
	}
	// and it reached the vault, so another process sees the rotated cookie
	other := NewPersistent(NewStore(openVault(t, dir)))
	e, ok := other.GetWithin(context.Background(), u, http.DefaultClient, time.Hour)
	if !ok || e.Session.Cookies[0].Value != "ROTATED-VALUE-123456" {
		t.Errorf("another process must see the rotated cookie: %+v %v", e, ok)
	}
}

func TestUpdateOfAnUnknownSessionDoesNothing(t *testing.T) {
	u, _ := url.Parse("https://nobody.example")
	c := New()
	if c.Update(u, sample("good")) {
		t.Error("there is nothing to update")
	}
	if len(c.List()) != 0 {
		t.Error("and it must not create a session out of thin air: a rotated cookie for a site nobody logged in to is not a login")
	}
}

func TestUpdateWithNilIsRefused(t *testing.T) {
	u, _ := url.Parse("https://nil.example")
	c := New()
	c.Put(u, probeDriver{}, sample("good"))
	if c.Update(u, nil) {
		t.Error("a nil session would wipe the login")
	}
	if _, ok := c.GetWithin(context.Background(), u, http.DefaultClient, time.Hour); !ok {
		t.Error("the session is untouched")
	}
}

// ---- a probe that cannot tell must not cost the person their login ----

// flakyProbe is what the registered flakyDriver answers. A session read back from the vault is given the driver the registry
// holds for its site name, not the one that was Put, so the answer has to live where every instance can reach it.
var flakyProbe error

type flakyDriver struct{ err *error }

func (flakyDriver) Name() string        { return "flaky" }
func (flakyDriver) Match(*url.URL) bool { return false }
func (flakyDriver) NeedsLogin() bool    { return true }
func (flakyDriver) Login(context.Context, *url.URL, site.Asker, *http.Client) (*site.Session, error) {
	return nil, errors.New("unused")
}
func (d flakyDriver) Probe(context.Context, *url.URL, *site.Session, *http.Client) error {
	if d.err != nil {
		return *d.err
	}
	return flakyProbe
}

func init() { site.Register(flakyDriver{}) }

// staleCache holds one session whose last validation is long ago, so that the next use probes it.
func staleCache(t *testing.T, probeErr *error, store *Store) (*Cache, *url.URL) {
	t.Helper()
	u, _ := url.Parse("https://flaky.example")
	c := New()
	if store != nil {
		c = NewPersistent(store)
	}
	c.Put(u, flakyDriver{probeErr}, sample("good"))
	c.mu.Lock()
	c.m[Key(u)].ValidatedAt = time.Now().Add(-time.Hour)
	c.mu.Unlock()
	return c, u
}

func TestAProbeThatCannotReachTheSiteKeepsTheSession(t *testing.T) {
	for name, err := range map[string]error{
		"unreachable":      fmt.Errorf("%w: connection refused", site.ErrUnreachable),
		"wrapped deeper":   fmt.Errorf("probe: %w", fmt.Errorf("%w: timeout", site.ErrUnreachable)),
		"bare unreachable": site.ErrUnreachable,
	} {
		probeErr := err
		c, u := staleCache(t, &probeErr, nil)
		e, gotErr := c.Lookup(context.Background(), u, http.DefaultClient, time.Minute)
		if e != nil || !errors.Is(gotErr, site.ErrUnreachable) {
			t.Errorf("%s: the caller must be told the site could not be reached: %v %v", name, e, gotErr)
		}
		if _, still := c.m[Key(u)]; !still {
			t.Errorf("%s: the session must be kept in memory", name)
		}
	}
}

func TestAKeptSessionIsUsedAgainWhenTheSiteAnswers(t *testing.T) {
	probeErr := fmt.Errorf("%w: connection refused", site.ErrUnreachable)
	c, u := staleCache(t, &probeErr, nil)
	if _, err := c.Lookup(context.Background(), u, http.DefaultClient, time.Minute); !errors.Is(err, site.ErrUnreachable) {
		t.Fatalf("%v", err)
	}
	probeErr = nil // the VPN is back
	e, err := c.Lookup(context.Background(), u, http.DefaultClient, time.Minute)
	if err != nil || e == nil || e.Session.Tokens["t"] != "good" {
		t.Errorf("the same session must come back with its own credentials: %+v %v", e, err)
	}
}

func TestAKeptSessionSurvivesInTheVault(t *testing.T) {
	dir := t.TempDir()
	v := openVault(t, dir)
	store := NewStore(v)
	probeErr := fmt.Errorf("%w: connection refused", site.ErrUnreachable)
	c, u := staleCache(t, &probeErr, store)
	c.Lookup(context.Background(), u, http.DefaultClient, time.Minute)
	if _, ok := store.load()[Key(u)]; !ok {
		t.Fatal("the session must still be in the vault, or a restart would lose it")
	}
	probeErr, flakyProbe = nil, nil
	c2 := NewPersistent(NewStore(v)) // a new process
	if e, err := c2.Lookup(context.Background(), u, http.DefaultClient, time.Minute); err != nil || e == nil {
		t.Errorf("a new process finds it: %v %v", e, err)
	}
}

// What a driver that has not been taught the difference returns (a plain error) still ends the session, as before.
func TestAProbeThatRejectsTheSessionStillDropsIt(t *testing.T) {
	probeErr := errors.New("session invalid: 401 Unauthorized")
	c, u := staleCache(t, &probeErr, nil)
	e, err := c.Lookup(context.Background(), u, http.DefaultClient, time.Minute)
	if e != nil || err == nil || errors.Is(err, site.ErrUnreachable) {
		t.Errorf("a rejection is not 'cannot reach': %v %v", e, err)
	}
	if _, still := c.m[Key(u)]; still {
		t.Error("a session the site rejected must be dropped")
	}
	if _, ok := c.GetWithin(context.Background(), u, http.DefaultClient, time.Minute); ok {
		t.Error("and it stays gone")
	}
}

func TestBadCredentialsAreARejectionEvenWhenTheMessageSaysUnreachable(t *testing.T) {
	probeErr := fmt.Errorf("%w: the database refused that username or password (site unreachable)", site.ErrBadCredentials)
	c, u := staleCache(t, &probeErr, nil)
	c.Lookup(context.Background(), u, http.DefaultClient, time.Minute)
	if _, still := c.m[Key(u)]; still {
		t.Error("refused credentials end the session whatever else the text says")
	}
}

func TestAnExpiredSessionIsDroppedWithoutAsking(t *testing.T) {
	probes := 0
	u, _ := url.Parse("https://expired2.example")
	c := New()
	s := sample("good")
	s.ExpiresAt = time.Now().Add(-time.Second)
	c.Put(u, countingDriver{&probes}, s)
	e, err := c.Lookup(context.Background(), u, http.DefaultClient, 0)
	if e != nil || !errors.Is(err, ErrExpired) || probes != 0 {
		t.Errorf("%v %v probes=%d", e, err, probes)
	}
}

func TestNoSessionIsSaidAsNoSession(t *testing.T) {
	u, _ := url.Parse("https://never.example")
	if _, err := New().Lookup(context.Background(), u, http.DefaultClient, 0); !errors.Is(err, ErrNoSession) {
		t.Errorf("%v", err)
	}
}

// Every time a session is dropped by the cache itself, somebody can be told why.
func TestTheCacheSaysWhyItDroppedASession(t *testing.T) {
	type drop struct{ key, reason string }
	var got []drop
	rec := func(key, reason string) { got = append(got, drop{key, reason}) }

	probeErr := errors.New("session invalid")
	c, u := staleCache(t, &probeErr, nil)
	c.OnDrop = rec
	c.Lookup(context.Background(), u, http.DefaultClient, time.Minute)

	u2, _ := url.Parse("https://exp.example")
	s := sample("good")
	s.ExpiresAt = time.Now().Add(-time.Second)
	c.Put(u2, probeDriver{}, s)
	c.Lookup(context.Background(), u2, http.DefaultClient, 0)

	unreachable := fmt.Errorf("%w: x", site.ErrUnreachable)
	c3, u3 := staleCache(t, &unreachable, nil)
	c3.OnDrop = rec
	c3.Lookup(context.Background(), u3, http.DefaultClient, time.Minute)

	want := []drop{{Key(u), DropRejected}, {Key(u2), DropExpired}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("got %v, want %v (and nothing for the session that was kept)", got, want)
	}
}

func TestClosingASessionOnPurposeIsNotReportedAsADrop(t *testing.T) {
	var n int
	probeErr := error(nil)
	c, u := staleCache(t, &probeErr, nil)
	c.OnDrop = func(string, string) { n++ }
	c.Delete(Key(u))
	if n != 0 {
		t.Errorf("an explicit Delete is the caller's decision and the caller records it: %d", n)
	}
}

// Credentials that were refused end the session even when the same error also says the site could not be reached (the
// database driver words some refusals that way), and the check is by identity, so a message that merely mentions it does not.
func TestRefusedCredentialsEndTheSessionEvenIfTheErrorAlsoWrapsUnreachable(t *testing.T) {
	both := fmt.Errorf("%w: and also %w", site.ErrBadCredentials, site.ErrUnreachable)
	if cannotTell(both) {
		t.Error("an error that wraps BadCredentials is a rejection, whatever else it wraps")
	}
	probeErr := both
	c, u := staleCache(t, &probeErr, nil)
	if e, err := c.Lookup(context.Background(), u, http.DefaultClient, time.Minute); e != nil || errors.Is(err, site.ErrUnreachable) && !errors.Is(err, ErrRejected) {
		t.Errorf("%v %v", e, err)
	}
	if _, still := c.m[Key(u)]; still {
		t.Error("the session must be dropped")
	}
	text := errors.New("this mentions site unreachable only in its words")
	if cannotTell(text) {
		t.Error("a message is not a classification")
	}
}

// A session that is fresh is not probed at all, so a site that is down does not even matter for it.
func TestAFreshSessionIsNotProbedEvenWhenTheSiteIsDown(t *testing.T) {
	probeErr := fmt.Errorf("%w: down", site.ErrUnreachable)
	u, _ := url.Parse("https://fresh-down.example")
	c := New()
	c.Put(u, flakyDriver{&probeErr}, sample("good")) // Put counts as validated just now
	if e, err := c.Lookup(context.Background(), u, http.DefaultClient, time.Minute); err != nil || e == nil {
		t.Errorf("a session validated a moment ago is used without asking the site: %v %v", e, err)
	}
	// and with no freshness window it is asked, and the answer is "cannot reach", kept
	if e, err := c.Lookup(context.Background(), u, http.DefaultClient, 0); e != nil || !errors.Is(err, site.ErrUnreachable) {
		t.Errorf("%v %v", e, err)
	}
	if _, still := c.m[Key(u)]; !still {
		t.Error("kept")
	}
}
