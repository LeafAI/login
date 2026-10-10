package keyring

import (
	"bytes"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

func TestLimitsAndRotation(t *testing.T) {
	now := time.Now()
	p := NewPool(t.TempDir(), 3, time.Hour)
	p.now = func() time.Time { return now }

	var ids []string
	for i := 0; i < 3; i++ {
		k, err := p.Acquire()
		if err != nil {
			t.Fatal(err)
		}
		if k.Uses != i+1 {
			t.Errorf("use %d: got Uses=%d", i, k.Uses)
		}
		ids = append(ids, k.ID)
	}
	if ids[0] != ids[1] || ids[1] != ids[2] {
		t.Fatalf("key not reused: %v", ids)
	}
	k4, _ := p.Acquire() // max uses exhausted -> new key
	if k4.ID == ids[0] || k4.Uses != 1 {
		t.Fatalf("expected rotation, got %+v", k4)
	}
	now = now.Add(2 * time.Hour) // max age exceeded -> new key
	k5, _ := p.Acquire()
	if k5.ID == k4.ID {
		t.Fatal("expected age-based rotation")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	p := NewPool(t.TempDir(), 8, time.Hour)
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
	w, err := openpgp.Encrypt(aw, ents, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte(`{"hello":"world"}`))
	w.Close()
	aw.Close()
	got, err := k.Decrypt(buf.Bytes())
	if err != nil || string(got) != `{"hello":"world"}` {
		t.Fatalf("got %q, %v", got, err)
	}
	// A reloaded key from disk decrypts too.
	k2, _ := p.Acquire()
	if k2.ID != k.ID {
		t.Fatal("expected reuse")
	}
	if got, err := k2.Decrypt(buf.Bytes()); err != nil || len(got) == 0 {
		t.Fatalf("reload decrypt: %v", err)
	}
}
