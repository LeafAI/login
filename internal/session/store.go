package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/LeafAI/login/internal/filelock"
	"github.com/LeafAI/login/internal/site"
)

// Store persists sessions in an AES-256-GCM encrypted file so that a new MCP server process (every
// agent session starts one) can reuse a login without bothering the human again.
//
// The key lives next to the data (both 0600): this keeps sessions out of backups, greps and accidental
// disclosure, but it does not protect against another process running as the same user.
type Store struct {
	Dir string
}

type cookieJSON struct {
	Name     string    `json:"n"`
	Value    string    `json:"v"`
	Domain   string    `json:"d,omitempty"`
	Path     string    `json:"p,omitempty"`
	Expires  time.Time `json:"e,omitempty"`
	Secure   bool      `json:"s,omitempty"`
	HTTPOnly bool      `json:"h,omitempty"`
}

type record struct {
	Site       string            `json:"site"`
	Base       string            `json:"base"`
	Cookies    []cookieJSON      `json:"cookies,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Tokens     map[string]string `json:"tokens,omitempty"`
	ExpiresAt  time.Time         `json:"expires_at,omitempty"`
	ObtainedAt time.Time         `json:"obtained_at"`
}

func toRecord(e *Entry) record {
	r := record{Site: e.Site, Base: e.Base, Headers: e.Session.Headers, Tokens: e.Session.Tokens,
		ExpiresAt: e.Session.ExpiresAt, ObtainedAt: e.ObtainedAt}
	for _, c := range e.Session.Cookies {
		r.Cookies = append(r.Cookies, cookieJSON{c.Name, c.Value, c.Domain, c.Path, c.Expires, c.Secure, c.HttpOnly})
	}
	return r
}

func (r record) session() *site.Session {
	s := &site.Session{Headers: r.Headers, Tokens: r.Tokens, ExpiresAt: r.ExpiresAt}
	for _, c := range r.Cookies {
		s.Cookies = append(s.Cookies, &http.Cookie{Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path,
			Expires: c.Expires, Secure: c.Secure, HttpOnly: c.HTTPOnly})
	}
	return s
}

func (s *Store) dataPath() string { return filepath.Join(s.Dir, "sessions.enc") }
func (s *Store) keyPath() string  { return filepath.Join(s.Dir, "sessions.key") }

func (s *Store) aead(create bool) (cipher.AEAD, error) {
	key, err := os.ReadFile(s.keyPath())
	if errors.Is(err, os.ErrNotExist) && create {
		key = make([]byte, 32)
		rand.Read(key)
		if err := os.MkdirAll(s.Dir, 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(s.keyPath(), key, 0o600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("session store: bad key file")
	}
	b, _ := aes.NewCipher(key)
	return cipher.NewGCM(b)
}

// load returns the stored records; a missing, corrupt or foreign-key file reads as empty.
func (s *Store) load() map[string]record {
	out := map[string]record{}
	raw, err := os.ReadFile(s.dataPath())
	if err != nil {
		return out
	}
	g, err := s.aead(false)
	if err != nil || len(raw) < g.NonceSize() {
		return out
	}
	plain, err := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], nil)
	if err != nil {
		return out
	}
	var list []record
	if json.Unmarshal(plain, &list) != nil {
		return out
	}
	for _, r := range list {
		out[r.Base] = r
	}
	return out
}

func (s *Store) save(m map[string]record) error {
	g, err := s.aead(true)
	if err != nil {
		return err
	}
	list := make([]record, 0, len(m))
	for _, r := range m {
		list = append(list, r)
	}
	plain, _ := json.Marshal(list)
	nonce := make([]byte, g.NonceSize())
	rand.Read(nonce)
	tmp := s.dataPath() + ".tmp"
	if err := os.WriteFile(tmp, append(nonce, g.Seal(nil, nonce, plain, nil)...), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.dataPath())
}

// update runs fn on the current records under a cross-process lock and saves the result.
func (s *Store) update(fn func(map[string]record)) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	unlock, err := filelock.Lock(filepath.Join(s.Dir, ".lock"))
	if err != nil {
		return err
	}
	defer unlock()
	m := s.load()
	fn(m)
	return s.save(m)
}
