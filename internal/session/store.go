package session

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/vault"
)

// Store persists sessions in the vault, so that a new MCP server process (every agent session starts one) can reuse a
// login without bothering the human again. Nothing is written outside the vault: there is no key file next to the data,
// and while the vault is locked the store holds nothing and gives nothing.
type Store struct {
	v *vault.Vault
}

// NewStore returns a store that keeps its records in v, under the "session/" prefix.
func NewStore(v *vault.Vault) *Store { return &Store{v: v} }

const prefix = "session/"

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

func entryName(base string) string { return prefix + base }

// load returns the stored records. A record that cannot be read is skipped, so one bad entry hides no other; a locked
// vault reads as empty.
func (s *Store) load() map[string]record {
	out := map[string]record{}
	for _, name := range s.v.Keys(prefix) {
		raw, err := s.v.Get(name)
		if err != nil {
			continue
		}
		var r record
		if json.Unmarshal(raw, &r) != nil || r.Base == "" || entryName(r.Base) != name {
			continue
		}
		out[r.Base] = r
	}
	return out
}

// update applies fn to the stored records and writes back what changed. The vault's own locking makes each write safe
// across processes; fn sees a snapshot and may add or remove records.
func (s *Store) update(fn func(map[string]record)) error {
	before := s.load()
	after := map[string]record{}
	for k, r := range before {
		after[k] = r
	}
	fn(after)
	for base, r := range after {
		if old, had := before[base]; had && sameRecord(old, r) {
			continue
		}
		raw, err := json.Marshal(r)
		if err != nil {
			return err
		}
		if err := s.v.Put(entryName(base), raw); err != nil {
			return err
		}
	}
	for base := range before {
		if _, kept := after[base]; !kept {
			if err := s.v.Delete(entryName(base)); err != nil {
				return err
			}
		}
	}
	return nil
}

func sameRecord(a, b record) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
