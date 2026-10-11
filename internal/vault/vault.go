// Package vault keeps every secret login holds (logged-in sessions, TOTP secrets) in one encrypted store that is
// locked when the process starts and opens only for the vault passphrase.
//
// Layout, in one 0700 directory:
//
//	header.json  the KDF parameters, a random salt, and the master key wrapped (AES-256-GCM) under a key that argon2id
//	             derives from the passphrase. Changing the passphrase rewrites only this file.
//	data.enc     every entry, sealed as one AES-256-GCM message under the master key. The additional data binds the
//	             vault's id and a write counter, so a file from another vault, or an older copy of this one, does not
//	             open or is refused.
//
// The master key exists in memory only while the vault is unlocked, and is overwritten when it locks.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"github.com/LeafAI/securl/internal/filelock"
)

const (
	headerFile = "header.json"
	dataFile   = "data.enc"
	// MinPassphraseRunes is the shortest passphrase the vault accepts.
	MinPassphraseRunes = 16
	formatVersion      = 1
)

// State is where the vault is in its life.
type State int

const (
	NotInitialized State = iota
	Locked
	Unlocked
)

func (s State) String() string {
	return [...]string{"not_initialized", "locked", "unlocked"}[s]
}

var (
	ErrNotInitialized     = errors.New("the vault has not been initialized (run `securl vault init`)")
	ErrAlreadyInitialized = errors.New("the vault is already initialized")
	ErrLocked             = errors.New("the vault is locked")
	ErrWrongPassphrase    = errors.New("wrong vault passphrase")
	ErrNoEntry            = errors.New("no such entry in the vault")
	ErrExists             = errors.New("the vault already has an entry with that name")
	ErrCorrupt            = errors.New("the vault files are damaged, were changed, or do not belong together")
)

// WeakPassphraseError says why a passphrase was refused.
type WeakPassphraseError struct{ Reason string }

func (e *WeakPassphraseError) Error() string { return "the vault passphrase is too weak: " + e.Reason }

// CheckPassphrase applies the passphrase rules: at least 16 characters, and not an obviously trivial string.
func CheckPassphrase(p string) error {
	if strings.TrimSpace(p) == "" {
		return &WeakPassphraseError{"it is empty"}
	}
	n := utf8.RuneCountInString(p)
	if n < MinPassphraseRunes {
		return &WeakPassphraseError{fmt.Sprintf("it has %d characters and at least %d are required", n, MinPassphraseRunes)}
	}
	if strings.TrimSpace(p) == "" {
		return &WeakPassphraseError{"it is only white space"}
	}
	distinct := map[rune]bool{}
	digits := true
	for _, r := range p {
		distinct[r] = true
		if r < '0' || r > '9' {
			digits = false
		}
	}
	switch {
	case len(distinct) < 5:
		return &WeakPassphraseError{"it uses too few different characters"}
	case digits:
		return &WeakPassphraseError{"it is only digits; use words or mix in other characters"}
	}
	return nil
}

type kdfParams struct {
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
}

func defaultKDF() kdfParams { return kdfParams{Time: 3, MemoryKiB: 64 * 1024, Threads: 4} }

// Bounds on what a header may ask for: a planted header must not make the process allocate gigabytes or spin for hours.
const (
	maxKDFTime   = 20
	maxKDFMemKiB = 1 << 21 // 2 GiB
	maxKDFThread = 32
)

func (p kdfParams) valid() bool {
	return p.Time >= 1 && p.Time <= maxKDFTime && p.MemoryKiB >= 8 && p.MemoryKiB <= maxKDFMemKiB && p.Threads >= 1 && p.Threads <= maxKDFThread
}

type header struct {
	Version int       `json:"version"`
	ID      []byte    `json:"id"` // names this vault; bound into every data file
	KDF     kdfParams `json:"kdf"`
	Salt    []byte    `json:"salt"`
	Nonce   []byte    `json:"nonce"`
	Wrapped []byte    `json:"wrapped"` // the master key sealed under the passphrase-derived key
}

type payload struct {
	Entries map[string][]byte `json:"entries"`
}

// Vault is one encrypted store. All methods are safe for concurrent use.
type Vault struct {
	dir string
	kdf kdfParams
	now func() time.Time

	mu       sync.Mutex
	master   []byte
	hdr      *header
	entries  map[string][]byte
	counter  uint64 // number of the data file this process last wrote or read
	idle     time.Duration
	lastUsed time.Time
}

// New returns the vault stored in dir (nothing is read or created yet).
func New(dir string) *Vault { return &Vault{dir: dir, kdf: defaultKDF(), now: time.Now} }

// NewWithCost is New with explicit argon2id parameters. It exists for tests of other packages, which would otherwise
// spend a second of key derivation on every vault they open; the parameters are recorded in the header and checked
// against the same bounds as any header, so a vault made this way is exactly as readable as any other. Production code
// uses New.
func NewWithCost(dir string, time, memoryKiB uint32, threads uint8) *Vault {
	v := New(dir)
	v.kdf = kdfParams{Time: time, MemoryKiB: memoryKiB, Threads: threads}
	return v
}

// Dir is the directory holding the vault.
func (v *Vault) Dir() string { return v.dir }

func (v *Vault) headerPath() string { return filepath.Join(v.dir, headerFile) }
func (v *Vault) dataPath() string   { return filepath.Join(v.dir, dataFile) }

// State reports whether the vault exists and whether it is open.
func (v *Vault) State() State {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.expireLocked()
	if v.master != nil {
		return Unlocked
	}
	if _, err := os.Stat(v.headerPath()); err != nil {
		return NotInitialized
	}
	return Locked
}

// SetIdleTimeout locks the vault after it has not been used for d (0 disables it).
func (v *Vault) SetIdleTimeout(d time.Duration) {
	v.mu.Lock()
	v.idle, v.lastUsed = d, v.now()
	v.mu.Unlock()
}

func (v *Vault) expireLocked() {
	if v.master != nil && v.idle > 0 && v.now().Sub(v.lastUsed) > v.idle {
		v.lockLocked()
	}
}

func (v *Vault) lockLocked() {
	wipe(v.master)
	v.master = nil
	for k, b := range v.entries {
		wipe(b)
		delete(v.entries, k)
	}
	v.entries = nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Lock forgets the master key and every decrypted entry.
func (v *Vault) Lock() {
	v.mu.Lock()
	v.lockLocked()
	v.mu.Unlock()
}

func deriveWrapKey(pass string, salt []byte, p kdfParams) []byte {
	return argon2.IDKey([]byte(pass), salt, p.Time, p.MemoryKiB, p.Threads, 32)
}

func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func random(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("vault: random source: %w", err)
	}
	return b, nil
}

func headerAAD(h *header) []byte {
	return append([]byte("securl-vault-header-v1|"), h.ID...)
}

// Init creates the vault under pass and leaves it unlocked. It never replaces an existing vault.
func (v *Vault) Init(pass string) error {
	if err := CheckPassphrase(pass); err != nil {
		return err
	}
	return v.withFileLock(func() error {
		if _, err := os.Stat(v.headerPath()); err == nil {
			return ErrAlreadyInitialized
		}
		master, err := random(32)
		if err != nil {
			return err
		}
		id, err := random(16)
		if err != nil {
			return err
		}
		h := &header{Version: formatVersion, ID: id, KDF: v.kdf}
		if err := wrapMaster(h, pass, master); err != nil {
			return err
		}
		v.mu.Lock()
		defer v.mu.Unlock()
		v.hdr, v.master, v.entries, v.counter = h, master, map[string][]byte{}, 0
		if err := v.saveDataLocked(); err != nil {
			v.lockLocked()
			return err
		}
		if err := writeFileAtomic(v.headerPath(), mustJSON(h)); err != nil {
			os.Remove(v.dataPath())
			v.lockLocked()
			return err
		}
		v.lastUsed = v.now()
		return nil
	})
}

func wrapMaster(h *header, pass string, master []byte) error {
	salt, err := random(16)
	if err != nil {
		return err
	}
	key := deriveWrapKey(pass, salt, h.KDF)
	defer wipe(key)
	g, err := gcm(key)
	if err != nil {
		return err
	}
	nonce, err := random(g.NonceSize())
	if err != nil {
		return err
	}
	h.Salt, h.Nonce = salt, nonce
	h.Wrapped = g.Seal(nil, nonce, master, headerAAD(h))
	return nil
}

func unwrapMaster(h *header, pass string) ([]byte, error) {
	if !h.KDF.valid() {
		return nil, fmt.Errorf("%w: the key-derivation parameters are out of range", ErrCorrupt)
	}
	key := deriveWrapKey(pass, h.Salt, h.KDF)
	defer wipe(key)
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	if len(h.Nonce) != g.NonceSize() {
		return nil, fmt.Errorf("%w: bad header", ErrCorrupt)
	}
	master, err := g.Open(nil, h.Nonce, h.Wrapped, headerAAD(h))
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	return master, nil
}

func (v *Vault) readHeader() (*header, error) {
	b, err := os.ReadFile(v.headerPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotInitialized
	}
	if err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}
	var h header
	if err := json.Unmarshal(b, &h); err != nil || h.Version != formatVersion || len(h.ID) == 0 {
		return nil, fmt.Errorf("%w: unreadable header", ErrCorrupt)
	}
	return &h, nil
}

// Unlock opens the vault with pass.
func (v *Vault) Unlock(pass string) error {
	h, err := v.readHeader()
	if err != nil {
		return err
	}
	master, err := unwrapMaster(h, pass)
	if err != nil {
		return err
	}
	entries, counter, err := loadData(v.dataPath(), master, h)
	if err != nil {
		wipe(master)
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.master != nil {
		v.lockLocked()
	}
	v.hdr, v.master, v.entries, v.counter, v.lastUsed = h, master, entries, counter, v.now()
	return nil
}

func dataAAD(h *header, counter uint64) []byte {
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], counter)
	return append(append([]byte("securl-vault-data-v1|"), h.ID...), c[:]...)
}

// loadData reads and opens the data file. The first 8 bytes are the write counter, which the additional data binds.
func loadData(path string, master []byte, h *header) (map[string][]byte, uint64, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, fmt.Errorf("%w: the data file is missing", ErrCorrupt)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("vault: %w", err)
	}
	g, err := gcm(master)
	if err != nil {
		return nil, 0, err
	}
	if len(raw) < 8+g.NonceSize() {
		return nil, 0, fmt.Errorf("%w: the data file is truncated", ErrCorrupt)
	}
	counter := binary.BigEndian.Uint64(raw[:8])
	plain, err := g.Open(nil, raw[8:8+g.NonceSize()], raw[8+g.NonceSize():], dataAAD(h, counter))
	if err != nil {
		return nil, 0, ErrCorrupt
	}
	defer wipe(plain)
	var p payload
	if err := json.Unmarshal(plain, &p); err != nil {
		return nil, 0, fmt.Errorf("%w: unreadable contents", ErrCorrupt)
	}
	if p.Entries == nil {
		p.Entries = map[string][]byte{}
	}
	return p.Entries, counter, nil
}

// saveDataLocked writes the entries under the next counter value. The caller holds both v.mu and the directory's file
// lock (see withFileLock). A data file that is not the one this process last wrote or read (another process wrote it,
// or an old copy was put back) is refused rather than overwritten.
func (v *Vault) saveDataLocked() error {
	if v.counter > 0 || fileExists(v.dataPath()) {
		cur, err := currentCounter(v.dataPath())
		if err != nil {
			return err
		}
		if cur != v.counter {
			return fmt.Errorf("%w: the data file is at write %d, this process expected %d", ErrCorrupt, cur, v.counter)
		}
	}
	next := v.counter + 1
	plain, err := json.Marshal(payload{Entries: v.entries})
	if err != nil {
		return err
	}
	defer wipe(plain)
	g, err := gcm(v.master)
	if err != nil {
		return err
	}
	nonce, err := random(g.NonceSize())
	if err != nil {
		return err
	}
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], next)
	out := append(append(c[:], nonce...), g.Seal(nil, nonce, plain, dataAAD(v.hdr, next))...)
	if err := writeFileAtomic(v.dataPath(), out); err != nil {
		return err
	}
	v.counter = next
	return nil
}

// syncLocked brings the entries up to date with the data file when another process has written it since. The caller
// holds v.mu and the directory's file lock. Only progress is accepted: a data file at a lower write than this process has
// seen is an old copy put back, and is refused.
func (v *Vault) syncLocked() error {
	cur, err := currentCounter(v.dataPath())
	if err != nil {
		return err
	}
	switch {
	case cur == v.counter:
		return nil
	case cur < v.counter:
		return fmt.Errorf("%w: the data file is at write %d, this process has already seen write %d", ErrCorrupt, cur, v.counter)
	}
	entries, counter, err := loadData(v.dataPath(), v.master, v.hdr)
	if err != nil {
		return err
	}
	for k, b := range v.entries {
		wipe(b)
		delete(v.entries, k)
	}
	v.entries, v.counter = entries, counter
	return nil
}

// refreshForward picks up writes of other processes before a read. It is best-effort: when the file cannot be read or
// has not advanced, the read is served from memory (a rollback is only refused when something is written).
func (v *Vault) refreshForward() {
	cur, err := currentCounter(v.dataPath())
	if err != nil || cur <= v.counter {
		return
	}
	entries, counter, err := loadData(v.dataPath(), v.master, v.hdr)
	if err != nil {
		return
	}
	for k, b := range v.entries {
		wipe(b)
		delete(v.entries, k)
	}
	v.entries, v.counter = entries, counter
}

func currentCounter(path string) (uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("%w: the data file is missing", ErrCorrupt)
	}
	defer f.Close()
	var c [8]byte
	if _, err := io.ReadFull(f, c[:]); err != nil {
		return 0, fmt.Errorf("%w: the data file is truncated", ErrCorrupt)
	}
	return binary.BigEndian.Uint64(c[:]), nil
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic("vault: " + err.Error()) // the types here always marshal
	}
	return b
}

func writeFileAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("vault: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("vault: %w", err)
	}
	return nil
}

// withFileLock runs fn while holding the cross-process lock of the vault directory.
func (v *Vault) withFileLock(fn func() error) error {
	if err := os.MkdirAll(v.dir, 0o700); err != nil {
		return fmt.Errorf("vault: %w", err)
	}
	unlock, err := filelock.Lock(filepath.Join(v.dir, ".lock"))
	if err != nil {
		return fmt.Errorf("vault: %w", err)
	}
	defer unlock()
	return fn()
}

// open runs fn with the vault unlocked, refreshing the idle clock.
func (v *Vault) open(fn func() error) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.expireLocked()
	if v.master == nil {
		if _, err := os.Stat(v.headerPath()); err != nil {
			return ErrNotInitialized
		}
		return ErrLocked
	}
	v.lastUsed = v.now()
	return fn()
}

// Get returns a copy of an entry.
func (v *Vault) Get(key string) ([]byte, error) {
	var out []byte
	err := v.open(func() error {
		v.refreshForward()
		b, ok := v.entries[key]
		if !ok {
			return ErrNoEntry
		}
		out = append([]byte{}, b...)
		return nil
	})
	return out, err
}

// Put stores a copy of value under key.
func (v *Vault) Put(key string, value []byte) error {
	return v.open(func() error {
		return v.withFileLock(func() error {
			if err := v.syncLocked(); err != nil {
				return err
			}
			prev, had := v.entries[key]
			v.entries[key] = append([]byte{}, value...)
			if err := v.saveDataLocked(); err != nil {
				if had {
					v.entries[key] = prev
				} else {
					delete(v.entries, key)
				}
				return err
			}
			wipe(prev)
			return nil
		})
	})
}

// PutNew stores value under key only if there is no such entry. The check and the write happen under the directory's
// lock against the current file, so two processes cannot both create the same entry. Secrets that other people have
// already registered somewhere (a TOTP secret in an authenticator) are written this way: replacing one would lock them out.
func (v *Vault) PutNew(key string, value []byte) error {
	return v.open(func() error {
		return v.withFileLock(func() error {
			if err := v.syncLocked(); err != nil {
				return err
			}
			if _, ok := v.entries[key]; ok {
				return ErrExists
			}
			v.entries[key] = append([]byte{}, value...)
			if err := v.saveDataLocked(); err != nil {
				delete(v.entries, key)
				return err
			}
			return nil
		})
	})
}

// Delete removes an entry; removing one that is not there is not an error.
func (v *Vault) Delete(key string) error {
	return v.open(func() error {
		return v.withFileLock(func() error {
			if err := v.syncLocked(); err != nil {
				return err
			}
			prev, ok := v.entries[key]
			if !ok {
				return nil
			}
			delete(v.entries, key)
			if err := v.saveDataLocked(); err != nil {
				v.entries[key] = prev
				return err
			}
			wipe(prev)
			return nil
		})
	})
}

// Keys lists the entry names that start with prefix, sorted.
func (v *Vault) Keys(prefix string) []string {
	var out []string
	_ = v.open(func() error {
		v.refreshForward()
		for k := range v.entries {
			if strings.HasPrefix(k, prefix) {
				out = append(out, k)
			}
		}
		return nil
	})
	sort.Strings(out)
	return out
}

// DeriveKey returns a 32-byte key for one purpose, derived from the master key (HMAC-SHA-256 as a PRF). The same
// purpose always gives the same key for the same vault, and different purposes give unrelated keys, so a part of
// login that needs its own encryption key (the session file, say) never holds a key that lives outside the vault.
func (v *Vault) DeriveKey(purpose string) ([]byte, error) {
	var out []byte
	err := v.open(func() error {
		m := hmac.New(sha256.New, v.master)
		m.Write([]byte("securl-vault-derive-v1|" + purpose))
		out = m.Sum(nil)
		return nil
	})
	return out, err
}

// Change re-wraps the master key under a new passphrase. Entries are not touched.
func (v *Vault) Change(oldPass, newPass string) error {
	if err := CheckPassphrase(newPass); err != nil {
		return err
	}
	if oldPass == newPass {
		return &WeakPassphraseError{"it is the same as the current one"}
	}
	return v.withFileLock(func() error {
		h, err := v.readHeader()
		if err != nil {
			return err
		}
		master, err := unwrapMaster(h, oldPass)
		if err != nil {
			return err
		}
		defer wipe(master)
		h.KDF = v.kdf
		if err := wrapMaster(h, newPass, master); err != nil {
			return err
		}
		if err := writeFileAtomic(v.headerPath(), mustJSON(h)); err != nil {
			return err
		}
		v.mu.Lock()
		if v.master != nil {
			v.hdr = h
		}
		v.mu.Unlock()
		return nil
	})
}
