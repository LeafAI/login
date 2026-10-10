// Package keyring manages the short-lived OpenPGP key pairs used to protect credentials in transit.
//
// A key pair may serve at most MaxUses login requests and live at most MaxAge; afterwards it is
// deleted and a new one is generated.
package keyring

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/LeafAI/login/internal/filelock"
)

type Pool struct {
	Dir     string
	MaxUses int
	MaxAge  time.Duration
	now     func() time.Time
}

func NewPool(dir string, maxUses int, maxAge time.Duration) *Pool {
	return &Pool{Dir: dir, MaxUses: maxUses, MaxAge: maxAge, now: time.Now}
}

type meta struct {
	CreatedAt time.Time `json:"created_at"`
	Uses      int       `json:"uses"`
}

// Key is a usable key pair handed out by Acquire.
type Key struct {
	ID     string
	Entity *openpgp.Entity
	Uses   int // uses including this one
}

// Acquire returns a live key (fewest remaining uses first), counting one use, or generates a new one.
func (p *Pool) Acquire() (*Key, error) {
	if err := os.MkdirAll(p.Dir, 0o700); err != nil {
		return nil, err
	}
	unlock, err := p.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	files, _ := filepath.Glob(filepath.Join(p.Dir, "*.json"))
	var bestID string
	var best meta
	for _, f := range files {
		id := strings.TrimSuffix(filepath.Base(f), ".json")
		m, err := readMeta(f)
		if err != nil || p.expired(m) {
			p.remove(id)
			continue
		}
		if bestID == "" || m.Uses > best.Uses {
			bestID, best = id, m
		}
	}
	if bestID != "" {
		ent, err := readEntity(p.privPath(bestID))
		if err == nil {
			best.Uses++
			if err := writeJSON(p.metaPath(bestID), best); err != nil {
				return nil, err
			}
			return &Key{ID: bestID, Entity: ent, Uses: best.Uses}, nil
		}
		p.remove(bestID)
	}
	return p.generate()
}

func (p *Pool) expired(m meta) bool {
	return m.Uses >= p.MaxUses || p.now().Sub(m.CreatedAt) >= p.MaxAge
}

func (p *Pool) generate() (*Key, error) {
	cfg := &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Time: p.now}
	ent, err := openpgp.NewEntity("login", "", "login@localhost", cfg)
	if err != nil {
		return nil, err
	}
	var id [8]byte
	rand.Read(id[:])
	name := hex.EncodeToString(id[:])
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		return nil, err
	}
	if err := ent.SerializePrivate(w, nil); err != nil {
		return nil, err
	}
	w.Close()
	if err := os.WriteFile(p.privPath(name), buf.Bytes(), 0o600); err != nil {
		return nil, err
	}
	if err := writeJSON(p.metaPath(name), meta{CreatedAt: p.now(), Uses: 1}); err != nil {
		return nil, err
	}
	return &Key{ID: name, Entity: ent, Uses: 1}, nil
}

func (p *Pool) privPath(id string) string { return filepath.Join(p.Dir, id+".asc") }
func (p *Pool) metaPath(id string) string { return filepath.Join(p.Dir, id+".json") }
func (p *Pool) remove(id string)          { os.Remove(p.privPath(id)); os.Remove(p.metaPath(id)) }

func readMeta(path string) (meta, error) {
	var m meta
	b, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	return m, json.Unmarshal(b, &m)
}

func writeJSON(path string, v any) error {
	b, _ := json.Marshal(v)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readEntity(path string) (*openpgp.Entity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	list, err := openpgp.ReadArmoredKeyRing(f)
	if err != nil || len(list) == 0 {
		return nil, fmt.Errorf("read key: %v", err)
	}
	return list[0], nil
}

func (p *Pool) lock() (func(), error) { return filelock.Lock(filepath.Join(p.Dir, ".lock")) }

// PublicKeyBinary is the transferable public key in binary OpenPGP packet form.
func (k *Key) PublicKeyBinary() ([]byte, error) {
	var buf bytes.Buffer
	if err := k.Entity.Serialize(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Fingerprint is the upper-case hex fingerprint of the primary key.
func (k *Key) Fingerprint() string {
	return strings.ToUpper(hex.EncodeToString(k.Entity.PrimaryKey.Fingerprint))
}

// Decrypt decrypts an ASCII-armored (or raw binary) OpenPGP message.
func (k *Key) Decrypt(msg []byte) ([]byte, error) {
	var r io.Reader = bytes.NewReader(msg)
	if bytes.HasPrefix(bytes.TrimSpace(msg), []byte("-----BEGIN")) {
		blk, err := armor.Decode(bytes.NewReader(msg))
		if err != nil {
			return nil, err
		}
		r = blk.Body
	}
	md, err := openpgp.ReadMessage(r, openpgp.EntityList{k.Entity}, nil, nil)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(md.UnverifiedBody, 1<<20))
}
