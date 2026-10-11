package keyring

import (
	"bytes"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// Keys are kept in memory only: no private key is ever written to disk, because a key on disk would outlive the vault
// that is meant to guard everything else.

func TestMemoryPoolWritesNothingToDisk(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir) // a stray relative write would land here
	p := NewMemoryPool(3, time.Hour)
	for i := 0; i < 5; i++ {
		if _, err := p.Acquire(); err != nil {
			t.Fatal(err)
		}
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 0 {
		t.Errorf("a memory pool must not create files, found %d", len(ents))
	}
}

func TestMemoryPoolLimitsAndRotation(t *testing.T) {
	now := time.Now()
	p := NewMemoryPool(3, time.Hour)
	p.now = func() time.Time { return now }
	var ids []string
	for i := 0; i < 3; i++ {
		k, err := p.Acquire()
		if err != nil {
			t.Fatal(err)
		}
		if k.Uses != i+1 {
			t.Errorf("use %d: Uses=%d", i, k.Uses)
		}
		ids = append(ids, k.ID)
	}
	if ids[0] != ids[1] || ids[1] != ids[2] {
		t.Fatalf("key not reused: %v", ids)
	}
	k4, _ := p.Acquire()
	if k4.ID == ids[0] || k4.Uses != 1 {
		t.Fatalf("expected rotation after the uses ran out: %+v", k4)
	}
	now = now.Add(2 * time.Hour)
	if k5, _ := p.Acquire(); k5.ID == k4.ID {
		t.Fatal("expected rotation after the age ran out")
	}
}

func TestMemoryPoolKeysDecrypt(t *testing.T) {
	p := NewMemoryPool(8, time.Hour)
	k, err := p.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := k.PublicKeyBinary()
	ents, err := openpgp.ReadKeyRing(bytes.NewReader(pub))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	aw, _ := armor.Encode(&buf, "PGP MESSAGE", nil)
	w, _ := openpgp.Encrypt(aw, ents, nil, nil, nil)
	w.Write([]byte("hello"))
	w.Close()
	aw.Close()
	k2, _ := p.Acquire()
	if k2.ID != k.ID {
		t.Fatal("expected reuse")
	}
	if got, err := k2.Decrypt(buf.Bytes()); err != nil || string(got) != "hello" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestMemoryPoolIsSafeForConcurrentUse(t *testing.T) {
	p := NewMemoryPool(50, time.Hour)
	var wg sync.WaitGroup
	var mu sync.Mutex
	perID := map[string]int{}
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			k, err := p.Acquire()
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			perID[k.ID]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	for id, n := range perID {
		if n > 50 {
			t.Errorf("key %s was handed out %d times, more than its limit", id, n)
		}
	}
}

func TestMemoryPoolDifferentPoolsHaveDifferentKeys(t *testing.T) {
	a, _ := NewMemoryPool(8, time.Hour).Acquire()
	b, _ := NewMemoryPool(8, time.Hour).Acquire()
	if a.Fingerprint() == b.Fingerprint() {
		t.Error("two pools must not share a key")
	}
}

func TestMemoryPoolUsesOneKeyUntilItsLimitNotOnePerCall(t *testing.T) {
	p := NewMemoryPool(8, time.Hour)
	first, _ := p.Acquire()
	second, _ := p.Acquire()
	if first.Fingerprint() != second.Fingerprint() {
		t.Error("the same key must serve several logins up to its limit")
	}
}

func TestKeyCanBeForgotten(t *testing.T) {
	p := NewMemoryPool(8, time.Hour)
	k, _ := p.Acquire()
	p.Forget()
	k2, _ := p.Acquire()
	if k2.ID == k.ID {
		t.Error("after Forget the next key must be a new one: locking the vault must drop the keys that were in use")
	}
}
