package keyring

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Source hands out the key pairs that protect a login in transit.
type Source interface {
	Acquire() (*Key, error)
}

// MemoryPool is a Pool whose keys never leave memory. A transport key is short-lived by design (a few uses, a day at
// most), so nothing is lost by not keeping it across restarts, and nothing is left on disk for the vault to not protect.
// Locking the vault forgets the keys.
type MemoryPool struct {
	MaxUses int
	MaxAge  time.Duration
	now     func() time.Time

	mu      sync.Mutex
	current *memKey
}

type memKey struct {
	key     *Key
	created time.Time
}

// NewMemoryPool returns a pool that rotates its key after maxUses logins or maxAge.
func NewMemoryPool(maxUses int, maxAge time.Duration) *MemoryPool {
	return &MemoryPool{MaxUses: maxUses, MaxAge: maxAge, now: time.Now}
}

// Acquire returns the live key, counting one use, or makes a new one when there is none or it has run out.
func (p *MemoryPool) Acquire() (*Key, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c := p.current; c != nil && c.key.Uses < p.MaxUses && p.now().Sub(c.created) < p.MaxAge {
		c.key.Uses++
		out := *c.key
		return &out, nil
	}
	ent, err := openpgp.NewEntity("securl", "", "securl@localhost", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Time: p.now})
	if err != nil {
		return nil, fmt.Errorf("keyring: new key: %w", err)
	}
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, fmt.Errorf("keyring: random source: %w", err)
	}
	k := &Key{ID: hex.EncodeToString(id[:]), Entity: ent, Uses: 1}
	p.current = &memKey{key: k, created: p.now()}
	out := *k
	return &out, nil
}

// Forget drops the key in use; the next Acquire makes a new one.
func (p *MemoryPool) Forget() {
	p.mu.Lock()
	p.current = nil
	p.mu.Unlock()
}

var _ Source = (*MemoryPool)(nil)
