package session

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/site"
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

func TestPersistAcrossProcessesAndEncryption(t *testing.T) {
	dir := t.TempDir()
	u, _ := url.Parse("https://site.example/some/path")
	a := NewPersistent(&Store{Dir: dir})
	a.Put(u, probeDriver{}, sample("good"))

	// The file must not contain secrets in the clear, and must be private.
	raw, err := os.ReadFile(filepath.Join(dir, "sessions.enc"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"SECRET-COOKIE-VALUE", "SECRET-BEARER", "site.example"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("plaintext %q found in the store file", secret)
		}
	}
	for _, f := range []string{"sessions.enc", "sessions.key"} {
		if st, _ := os.Stat(filepath.Join(dir, f)); st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", f, st.Mode().Perm())
		}
	}

	// A different Cache (another process) sees the session, probes it, and gets the cookie details back.
	b := NewPersistent(&Store{Dir: dir})
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
	if _, ok := NewPersistent(&Store{Dir: dir}).Get(context.Background(), u, http.DefaultClient); ok {
		t.Error("deleted session still available")
	}
}

func TestStaleSessionDroppedFromStore(t *testing.T) {
	dir := t.TempDir()
	u, _ := url.Parse("https://stale.example")
	NewPersistent(&Store{Dir: dir}).Put(u, probeDriver{}, sample("bad"))
	c := NewPersistent(&Store{Dir: dir})
	if _, ok := c.Get(context.Background(), u, http.DefaultClient); ok {
		t.Fatal("stale session was returned")
	}
	if len((&Store{Dir: dir}).load()) != 0 {
		t.Error("stale session not removed from the store")
	}
}

func TestCorruptOrForeignKeyStoreReadsEmpty(t *testing.T) {
	dir := t.TempDir()
	u, _ := url.Parse("https://x.example")
	NewPersistent(&Store{Dir: dir}).Put(u, probeDriver{}, sample("good"))
	os.WriteFile(filepath.Join(dir, "sessions.key"), bytes.Repeat([]byte{7}, 32), 0o600) // different key
	if _, ok := NewPersistent(&Store{Dir: dir}).Get(context.Background(), u, http.DefaultClient); ok {
		t.Error("session decrypted with the wrong key")
	}
	os.WriteFile(filepath.Join(dir, "sessions.enc"), []byte("garbage"), 0o600)
	if n := len((&Store{Dir: dir}).load()); n != 0 {
		t.Errorf("garbage store loaded %d records", n)
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
