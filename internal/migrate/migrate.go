// Package migrate moves what earlier versions of login kept in plain files into the vault: the TOTP secrets, the
// stored sessions and the transport keys. A file is removed only after what it held has been read back from the vault.
package migrate

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/LeafAI/securl/internal/totp"
	"github.com/LeafAI/securl/internal/vault"
)

// Store is the part of the vault that migration needs.
type Store interface {
	Get(key string) ([]byte, error)
	PutNew(key string, value []byte) error
}

// Paths locates the files an earlier version made.
type Paths struct {
	LinkSecret  string // totp/link.secret
	SealSecret  string // totp/seal.secret
	SessionsDir string // holds sessions.enc and sessions.key
	KeysDir     string // holds the transport key files
}

// Report says what was done. It never contains a secret.
type Report struct {
	TOTP      int      // secrets moved into the vault
	Sessions  int      // sessions moved into the vault
	Keys      int      // transport key files removed
	Conflicts []string // a file whose secret differs from the one in the vault: kept
	Skipped   []string // something that could not be read or stored: kept
	Exposed   []string // a legacy secret file other users could read: rotate that secret
}

// Total is the number of things changed.
func (r Report) Total() int { return r.TOTP + r.Sessions + r.Keys }

func (r Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "moved into the vault: %d TOTP secret(s), %d session(s); removed %d old transport key file(s)\n", r.TOTP, r.Sessions, r.Keys)
	for _, s := range r.Conflicts {
		fmt.Fprintf(&b, "  CONFLICT: %s\n", s)
	}
	for _, s := range r.Skipped {
		fmt.Fprintf(&b, "  kept: %s\n", s)
	}
	for _, s := range r.Exposed {
		fmt.Fprintf(&b, "  WARNING: %s\n", s)
	}
	return b.String()
}

// remove deletes a file; a variable so that a test can look at the file at that moment.
var remove = os.Remove

// Run migrates everything it finds. It is safe to run again: what is already moved is not found again.
func Run(v Store, p Paths) (Report, error) {
	var rep Report
	if _, err := v.Get("migrate/probe"); errors.Is(err, vault.ErrLocked) || errors.Is(err, vault.ErrNotInitialized) {
		return rep, err
	}
	for _, f := range []struct{ name, path string }{{"link", p.LinkSecret}, {"seal", p.SealSecret}} {
		moveTOTP(v, f.name, f.path, &rep)
	}
	moveSessions(v, p.SessionsDir, &rep)
	removeKeys(p.KeysDir, &rep)
	return rep, nil
}

func moveTOTP(v Store, name, path string, rep *Report) {
	if path == "" || !exists(path) {
		return
	}
	st, _ := os.Stat(path)
	raw, err := os.ReadFile(path)
	if err != nil {
		rep.Skipped = append(rep.Skipped, fmt.Sprintf("the %s TOTP secret file could not be read: %v", name, err))
		return
	}
	secret, err := totp.ParseSecret(string(raw))
	if err != nil {
		rep.Skipped = append(rep.Skipped, fmt.Sprintf("the %s TOTP secret file is not a valid secret, so it was left alone", name))
		return
	}
	text := []byte(totp.FormatSecret(secret))
	entry := "totp/" + name
	switch err := v.PutNew(entry, text); {
	case err == nil:
	case errors.Is(err, vault.ErrExists):
		have, gerr := v.Get(entry)
		if gerr != nil {
			rep.Skipped = append(rep.Skipped, fmt.Sprintf("the %s TOTP secret could not be compared with the vault: %v", name, gerr))
			return
		}
		if !sameSecret(have, text) {
			rep.Conflicts = append(rep.Conflicts, fmt.Sprintf("the %s TOTP secret file differs from the secret already in the vault; the vault's was kept and the file was left in place (it may be the one registered in your authenticator)", name))
			return
		}
		shred(path)
		return
	default:
		rep.Skipped = append(rep.Skipped, fmt.Sprintf("the %s TOTP secret could not be stored in the vault: %v", name, err))
		return
	}
	// Read it back: a store that accepted the write but cannot return it must not cost the person the only copy.
	back, err := v.Get(entry)
	if err != nil || !sameSecret(back, text) {
		rep.Skipped = append(rep.Skipped, fmt.Sprintf("the %s TOTP secret could not be read back from the vault, so the file was left in place", name))
		return
	}
	if st != nil && st.Mode().Perm()&0o077 != 0 {
		rep.Exposed = append(rep.Exposed, fmt.Sprintf("the %s TOTP secret file was readable by other users (mode %v): treat that secret as exposed and make a new one", name, st.Mode().Perm()))
	}
	shred(path)
	rep.TOTP++
}

func sameSecret(a, b []byte) bool {
	x, err1 := totp.ParseSecret(string(a))
	y, err2 := totp.ParseSecret(string(b))
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// shred overwrites a file before removing it, so that the secret is not left readable in the file's blocks (best
// effort: a journalling or copy-on-write file system may keep older copies, which is why the vault, not deletion,
// is the protection).
func shred(path string) {
	if st, err := os.Stat(path); err == nil && st.Mode().IsRegular() {
		if f, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
			f.Write(bytes.Repeat([]byte{0}, int(st.Size())))
			f.Sync()
			f.Close()
		}
	}
	remove(path)
}

type oldRecord struct {
	Site string `json:"site"`
	Base string `json:"base"`
}

func moveSessions(v Store, dir string, rep *Report) {
	if dir == "" {
		return
	}
	dataPath, keyPath := filepath.Join(dir, "sessions.enc"), filepath.Join(dir, "sessions.key")
	if !exists(dataPath) && !exists(keyPath) {
		return
	}
	records, err := readOldSessions(dataPath, keyPath)
	if err != nil {
		rep.Skipped = append(rep.Skipped, "the old session file could not be read ("+err.Error()+"), so it was left in place")
		return
	}
	stored := 0
	for _, raw := range records {
		var head oldRecord
		if json.Unmarshal(raw, &head) != nil || head.Base == "" {
			continue
		}
		switch err := v.PutNew("session/"+head.Base, raw); {
		case err == nil:
			stored++
		case errors.Is(err, vault.ErrExists): // the vault's own copy is newer than anything in an old file
		default:
			rep.Skipped = append(rep.Skipped, fmt.Sprintf("a session for %s could not be stored: %v; the old session file was left in place", head.Base, err))
			return
		}
	}
	rep.Sessions += stored
	shred(dataPath)
	shred(keyPath)
}

// readOldSessions decrypts the file the previous version wrote: AES-256-GCM, nonce first, key in a file beside it.
func readOldSessions(dataPath, keyPath string) ([]json.RawMessage, error) {
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, errors.New("its key file is missing")
	}
	raw, err := os.ReadFile(dataPath)
	if err != nil {
		return nil, errors.New("the data file is missing")
	}
	if len(key) != 32 {
		return nil, errors.New("its key file is not a valid key")
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	if len(raw) < g.NonceSize() {
		return nil, errors.New("the data file is truncated")
	}
	plain, err := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], nil)
	if err != nil {
		return nil, errors.New("it does not decrypt with its key")
	}
	var list []json.RawMessage
	if err := json.Unmarshal(plain, &list); err != nil {
		return nil, errors.New("its contents are not a session list")
	}
	return list, nil
}

// removeKeys deletes the transport key files an earlier version kept (private keys, valid for at most a day). Only
// files login made are touched: a directory the person shares with other files keeps them.
func removeKeys(dir string, rep *Report) {
	if dir == "" {
		return
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() {
			continue
		}
		switch {
		case name == ".lock" || name == ".lock.tmp":
			remove(filepath.Join(dir, name))
		case isKeyFile(name):
			shred(filepath.Join(dir, name))
			rep.Keys++
		}
	}
	if left, _ := os.ReadDir(dir); len(left) == 0 {
		os.Remove(dir)
	}
}

// isKeyFile matches <16 hex digits>.asc and .json, the names the key pool used.
func isKeyFile(name string) bool {
	base, ext, ok := strings.Cut(name, ".")
	if !ok || (ext != "asc" && ext != "json") || base == "" {
		return false
	}
	for _, c := range base {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}
