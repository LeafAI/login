package vault

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

const goodPass = "correct horse battery staple"

// fastKDF keeps the tests quick; the production cost is asserted separately.
func fast(v *Vault) *Vault { v.kdf = kdfParams{Time: 1, MemoryKiB: 8, Threads: 1}; return v }

func newVault(t *testing.T) (*Vault, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "vault")
	return fast(New(dir)), dir
}

func mustInit(t *testing.T, v *Vault) {
	t.Helper()
	if err := v.Init(goodPass); err != nil {
		t.Fatal(err)
	}
}

func TestPassphraseRules(t *testing.T) {
	for name, p := range map[string]string{
		"empty":       "",
		"short":       "abc123",
		"fifteen":     "123456789012345",
		"spaces only": strings.Repeat(" ", 20),
	} {
		if err := CheckPassphrase(p); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
	for name, p := range map[string]string{
		"exactly sixteen": "abcdefghijklmnop",
		"phrase":          goodPass,
		"unicode":         "春眠不觉晓处处闻啼鸟夜来风雨声花落知多少", // 20 characters, 60 bytes
	} {
		if err := CheckPassphrase(p); err != nil {
			t.Errorf("%s: must be accepted: %v", name, err)
		}
	}
	if err := CheckPassphrase("春眠不觉晓处处闻啼鸟夜来风雨声"[:3*8]); err == nil {
		t.Error("eight characters are not sixteen, however many bytes they take")
	}
	if err := CheckPassphrase(strings.Repeat("a", 16)); err == nil {
		t.Error("one repeated character is not a passphrase")
	}
	if err := CheckPassphrase("0123456789012345"); err == nil {
		t.Error("a bare run of digits is refused")
	}
	var weak *WeakPassphraseError
	if err := CheckPassphrase("short"); !errors.As(err, &weak) || weak.Reason == "" {
		t.Errorf("the refusal must say why: %v", err)
	}
}

func TestStateMachine(t *testing.T) {
	v, _ := newVault(t)
	if st := v.State(); st != NotInitialized {
		t.Fatalf("a new directory is %v", st)
	}
	if err := v.Unlock(goodPass); !errors.Is(err, ErrNotInitialized) {
		t.Errorf("unlocking nothing: %v", err)
	}
	if _, err := v.Get("x"); !errors.Is(err, ErrNotInitialized) {
		t.Errorf("reading from nothing: %v", err)
	}
	mustInit(t, v)
	if st := v.State(); st != Unlocked {
		t.Errorf("Init leaves the vault unlocked, got %v", st)
	}
	v.Lock()
	if st := v.State(); st != Locked {
		t.Errorf("after Lock: %v", st)
	}
	if _, err := v.Get("x"); !errors.Is(err, ErrLocked) {
		t.Errorf("reading while locked: %v", err)
	}
	if err := v.Put("x", []byte("y")); !errors.Is(err, ErrLocked) {
		t.Errorf("writing while locked: %v", err)
	}
	if err := v.Unlock(goodPass); err != nil {
		t.Fatal(err)
	}
	if st := v.State(); st != Unlocked {
		t.Errorf("after Unlock: %v", st)
	}
}

func TestInitRefusesWeakPassAndNeverOverwrites(t *testing.T) {
	v, dir := newVault(t)
	if err := v.Init("short"); err == nil {
		t.Fatal("a weak passphrase must be refused")
	}
	if v.State() != NotInitialized {
		t.Fatal("a refused Init must leave nothing behind")
	}
	mustInit(t, v)
	if err := v.Put("k", []byte("precious")); err != nil {
		t.Fatal(err)
	}
	if err := v.Init("another long passphrase here"); !errors.Is(err, ErrAlreadyInitialized) {
		t.Errorf("a second Init must not replace the vault: %v", err)
	}
	v2 := fast(New(dir))
	if err := v2.Unlock(goodPass); err != nil {
		t.Fatalf("the original passphrase must still work: %v", err)
	}
	if got, _ := v2.Get("k"); string(got) != "precious" {
		t.Errorf("the contents survived: %q", got)
	}
}

func TestWrongPassphrase(t *testing.T) {
	v, dir := newVault(t)
	mustInit(t, v)
	v.Lock()
	err := v.Unlock("not the right passphrase")
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("got %v", err)
	}
	if v.State() != Locked {
		t.Error("a wrong passphrase leaves it locked")
	}
	if err := fast(New(dir)).Unlock(goodPass[:len(goodPass)-1]); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("one character short is still wrong: %v", err)
	}
}

func TestEntriesRoundTripAcrossProcesses(t *testing.T) {
	v, dir := newVault(t)
	mustInit(t, v)
	want := map[string][]byte{"totp/link": []byte("L-secret"), "session/https://a": []byte(`{"cookie":"c"}`), "empty": {}, "binary": {0, 1, 2, 0xff}}
	for k, val := range want {
		if err := v.Put(k, val); err != nil {
			t.Fatal(err)
		}
	}
	v2 := fast(New(dir))
	if err := v2.Unlock(goodPass); err != nil {
		t.Fatal(err)
	}
	for k, val := range want {
		got, err := v2.Get(k)
		if err != nil || !bytes.Equal(got, val) {
			t.Errorf("%q: %q %v, want %q", k, got, err, val)
		}
	}
	if _, err := v2.Get("missing"); !errors.Is(err, ErrNoEntry) {
		t.Errorf("a missing entry is ErrNoEntry: %v", err)
	}
	keys := v2.Keys("session/")
	if len(keys) != 1 || keys[0] != "session/https://a" {
		t.Errorf("prefix listing: %v", keys)
	}
	if err := v2.Delete("empty"); err != nil {
		t.Fatal(err)
	}
	if _, err := v2.Get("empty"); !errors.Is(err, ErrNoEntry) {
		t.Errorf("deleted: %v", err)
	}
	if err := v2.Delete("empty"); err != nil {
		t.Errorf("deleting what is not there is not an error: %v", err)
	}
}

func TestNothingSensitiveIsOnDiskInTheClear(t *testing.T) {
	v, dir := newVault(t)
	mustInit(t, v)
	secrets := []string{"SUPER-SECRET-COOKIE-VALUE", "totp-secret-JBSWY3DPEHPK3PXP", "session-key-name-visible?"}
	v.Put("totp/link", []byte(secrets[0]))
	v.Put("session/https://internal.corp", []byte(secrets[1]))
	v.Put(secrets[2], []byte("x"))
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := os.ReadFile(p)
		for _, s := range append(secrets, goodPass, "internal.corp", "totp/link") {
			if bytes.Contains(b, []byte(s)) {
				t.Errorf("%s contains %q in the clear", p, s)
			}
		}
		if st, _ := os.Stat(p); st.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s is readable by others: %v", p, st.Mode())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(dir); st.Mode().Perm()&0o077 != 0 {
		t.Errorf("the directory is readable by others: %v", st.Mode())
	}
}

func TestTamperingIsDetected(t *testing.T) {
	v, dir := newVault(t)
	mustInit(t, v)
	v.Put("k", []byte("value"))
	data := filepath.Join(dir, dataFile)
	b, _ := os.ReadFile(data)
	b[len(b)/2] ^= 0x01
	os.WriteFile(data, b, 0o600)
	v2 := fast(New(dir))
	if err := v2.Unlock(goodPass); err == nil || errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("a modified data file must be reported as corrupt, not as a wrong passphrase: %v", err)
	} else if !errors.Is(err, ErrCorrupt) {
		t.Errorf("want ErrCorrupt, got %v", err)
	}
}

func TestDataFileCannotBeSwappedFromAnotherVault(t *testing.T) {
	a, dirA := newVault(t)
	mustInit(t, a)
	a.Put("k", []byte("from A"))
	b, dirB := newVault(t)
	if err := b.Init(goodPass); err != nil { // the very same passphrase
		t.Fatal(err)
	}
	other, _ := os.ReadFile(filepath.Join(dirA, dataFile))
	os.WriteFile(filepath.Join(dirB, dataFile), other, 0o600)
	b2 := fast(New(dirB))
	if err := b2.Unlock(goodPass); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a data file from another vault must not open even under the same passphrase: %v", err)
	}
}

func TestRollbackOfTheDataFileIsRefusedWhileRunning(t *testing.T) {
	v, dir := newVault(t)
	mustInit(t, v)
	v.Put("k", []byte("v1"))
	old, _ := os.ReadFile(filepath.Join(dir, dataFile))
	v.Put("k", []byte("v2"))
	os.WriteFile(filepath.Join(dir, dataFile), old, 0o600)
	if _, err := v.Get("k"); err != nil {
		t.Fatalf("a read is served from memory: %v", err)
	}
	if err := v.Put("other", []byte("x")); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a write over a data file that went back in time must be refused: %v", err)
	}
}

func TestChangePassphrase(t *testing.T) {
	v, dir := newVault(t)
	mustInit(t, v)
	v.Put("k", []byte("v"))
	newPass := "a completely different passphrase"
	if err := v.Change("wrong old passphrase value", newPass); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("the old passphrase must be right: %v", err)
	}
	if err := v.Change(goodPass, "short"); err == nil {
		t.Error("the new passphrase must pass the rules")
	}
	if err := v.Change(goodPass, goodPass); err == nil {
		t.Error("changing to the same passphrase is refused")
	}
	if err := v.Change(goodPass, newPass); err != nil {
		t.Fatal(err)
	}
	v2 := fast(New(dir))
	if err := v2.Unlock(goodPass); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("the old passphrase must stop working: %v", err)
	}
	if err := v2.Unlock(newPass); err != nil {
		t.Fatal(err)
	}
	if got, _ := v2.Get("k"); string(got) != "v" {
		t.Errorf("entries survive a change: %q", got)
	}
}

func TestChangeReKeysTheWrapperWithFreshSaltAndNonce(t *testing.T) {
	v, dir := newVault(t)
	mustInit(t, v)
	before, _ := os.ReadFile(filepath.Join(dir, headerFile))
	if err := v.Change(goodPass, "a completely different passphrase"); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, headerFile))
	if bytes.Equal(before, after) {
		t.Fatal("the header must change")
	}
}

func TestSamePassphraseGivesDifferentVaults(t *testing.T) {
	a, dirA := newVault(t)
	b, dirB := newVault(t)
	mustInit(t, a)
	mustInit(t, b)
	ha, _ := os.ReadFile(filepath.Join(dirA, headerFile))
	hb, _ := os.ReadFile(filepath.Join(dirB, headerFile))
	if bytes.Equal(ha, hb) {
		t.Fatal("two vaults with one passphrase must not share salt, nonce or wrapped key")
	}
}

func TestDeriveSubKeysAreStableAndSeparate(t *testing.T) {
	v, dir := newVault(t)
	mustInit(t, v)
	k1, err := v.DeriveKey("sessions")
	if err != nil || len(k1) != 32 {
		t.Fatalf("%x %v", k1, err)
	}
	k2, _ := v.DeriveKey("sessions")
	k3, _ := v.DeriveKey("other purpose")
	if !bytes.Equal(k1, k2) || bytes.Equal(k1, k3) {
		t.Error("a purpose gives one key, and different purposes give different keys")
	}
	v.Lock()
	if _, err := v.DeriveKey("sessions"); !errors.Is(err, ErrLocked) {
		t.Errorf("no keys while locked: %v", err)
	}
	v2 := fast(New(dir))
	v2.Unlock(goodPass)
	if k, _ := v2.DeriveKey("sessions"); !bytes.Equal(k, k1) {
		t.Error("the derived key must be the same after a restart")
	}
}

func TestLockWipesTheKeyFromMemory(t *testing.T) {
	v, _ := newVault(t)
	mustInit(t, v)
	v.mu.Lock()
	key := v.master
	v.mu.Unlock()
	if key == nil {
		t.Fatal("unlocked vault has a master key")
	}
	v.Lock()
	if !bytes.Equal(key, make([]byte, len(key))) {
		t.Error("Lock must overwrite the master key bytes, not just drop the reference")
	}
}

func TestAutoLock(t *testing.T) {
	v, _ := newVault(t)
	mustInit(t, v)
	now := time.Now()
	v.now = func() time.Time { return now }
	v.SetIdleTimeout(10 * time.Minute)
	v.Put("k", []byte("v"))
	now = now.Add(9 * time.Minute)
	if _, err := v.Get("k"); err != nil {
		t.Fatalf("still within the idle window: %v", err)
	}
	now = now.Add(9 * time.Minute) // the Get above counted as activity
	if _, err := v.Get("k"); err != nil {
		t.Fatalf("activity extends the window: %v", err)
	}
	now = now.Add(11 * time.Minute)
	if _, err := v.Get("k"); !errors.Is(err, ErrLocked) {
		t.Errorf("an idle vault locks itself: %v", err)
	}
	if v.State() != Locked {
		t.Error("State must report the lock")
	}
}

func TestConcurrentAccess(t *testing.T) {
	v, dir := newVault(t)
	mustInit(t, v)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			k := "k" + string(rune('a'+i))
			if err := v.Put(k, []byte(k)); err != nil {
				t.Error(err)
			}
			if got, err := v.Get(k); err != nil || string(got) != k {
				t.Errorf("%s: %q %v", k, got, err)
			}
		}(i)
	}
	wg.Wait()
	v2 := fast(New(dir))
	v2.Unlock(goodPass)
	if n := len(v2.Keys("")); n != 20 {
		t.Errorf("%d entries survived, want 20", n)
	}
}

func TestGetReturnsACopy(t *testing.T) {
	v, _ := newVault(t)
	mustInit(t, v)
	v.Put("k", []byte("abc"))
	a, _ := v.Get("k")
	a[0] = 'X'
	b, _ := v.Get("k")
	if string(b) != "abc" {
		t.Errorf("callers must not be able to change the stored value through a returned slice: %q", b)
	}
	in := []byte("def")
	v.Put("j", in)
	in[0] = 'Z'
	if got, _ := v.Get("j"); string(got) != "def" {
		t.Errorf("Put must copy its input: %q", got)
	}
}

func TestProductionKDFCost(t *testing.T) {
	p := defaultKDF()
	if p.MemoryKiB < 64*1024 || p.Time < 3 {
		t.Errorf("argon2id parameters are too cheap to resist guessing: %+v", p)
	}
	hdr := New(t.TempDir())
	if hdr.kdf != p {
		t.Error("a new vault must use the production parameters")
	}
}

func TestHeaderRecordsItsParameters(t *testing.T) {
	v, dir := newVault(t)
	mustInit(t, v)
	v.Lock()
	// a vault written with cheap parameters opens with them even by a process whose defaults differ
	v2 := New(dir)
	if err := v2.Unlock(goodPass); err != nil {
		t.Fatalf("parameters must come from the header, not from the process: %v", err)
	}
}

func TestHeaderRefusesAbsurdParameters(t *testing.T) {
	v, dir := newVault(t)
	mustInit(t, v)
	h := filepath.Join(dir, headerFile)
	b, _ := os.ReadFile(h)
	// A planted header must not make the process allocate gigabytes or loop for hours.
	for _, bad := range []string{`"memory_kib":8`, `"time":1`} {
		repl := strings.Replace(string(b), bad, strings.Replace(bad, bad[strings.LastIndex(bad, ":")+1:], "4000000000", 1), 1)
		os.WriteFile(h, []byte(repl), 0o600)
		if err := fast(New(dir)).Unlock(goodPass); err == nil {
			t.Errorf("%s: absurd parameters must be refused", bad)
		}
	}
}

// A data file is only valid for the vault it was written by, at the write it was written at. These tests would fail if
// the additional data of the seal stopped binding the vault's id or the write counter.

func TestDataFileFromAnotherVaultWithTheSamePassphraseAndKeyIsRefused(t *testing.T) {
	a, dirA := newVault(t)
	mustInit(t, a)
	a.Put("k", []byte("from A"))
	dirB := filepath.Join(t.TempDir(), "vault")
	if err := os.MkdirAll(dirB, 0o700); err != nil {
		t.Fatal(err)
	}
	// B is a copy of A's header (same master key, same passphrase) but a different vault id.
	hdr, _ := os.ReadFile(filepath.Join(dirA, headerFile))
	var h header
	if err := json.Unmarshal(hdr, &h); err != nil {
		t.Fatal(err)
	}
	h.ID = bytes.Repeat([]byte{0xAB}, len(h.ID))
	os.WriteFile(filepath.Join(dirB, headerFile), mustJSON(&h), 0o600)
	data, _ := os.ReadFile(filepath.Join(dirA, dataFile))
	os.WriteFile(filepath.Join(dirB, dataFile), data, 0o600)
	// The wrapped key was sealed with A's id in its additional data, so B's header does not even unwrap.
	if err := fast(New(dirB)).Unlock(goodPass); err == nil {
		t.Error("a header whose vault id was changed must not open")
	}
}

func TestDataFileCounterIsBoundIntoTheSeal(t *testing.T) {
	v, dir := newVault(t)
	mustInit(t, v)
	v.Put("k", []byte("v"))
	path := filepath.Join(dir, dataFile)
	b, _ := os.ReadFile(path)
	// Change only the counter in the clear prefix: the sealed part is untouched, so only the binding can notice.
	binary.BigEndian.PutUint64(b[:8], binary.BigEndian.Uint64(b[:8])+1)
	os.WriteFile(path, b, 0o600)
	if err := fast(New(dir)).Unlock(goodPass); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a rewritten counter must be detected: %v", err)
	}
}

func TestHeaderIDIsBoundIntoTheWrappedKey(t *testing.T) {
	v, dir := newVault(t)
	mustInit(t, v)
	v.Lock()
	hp := filepath.Join(dir, headerFile)
	raw, _ := os.ReadFile(hp)
	var h header
	json.Unmarshal(raw, &h)
	h.ID[0] ^= 0xFF
	os.WriteFile(hp, mustJSON(&h), 0o600)
	if err := fast(New(dir)).Unlock(goodPass); !errors.Is(err, ErrWrongPassphrase) && !errors.Is(err, ErrCorrupt) {
		t.Errorf("a header with another id must not unwrap: %v", err)
	}
}

func TestNewDataFileUnderANewCounterDiffersEvenForSameContent(t *testing.T) {
	v, dir := newVault(t)
	mustInit(t, v)
	v.Put("k", []byte("same"))
	one, _ := os.ReadFile(filepath.Join(dir, dataFile))
	v.Put("k", []byte("same"))
	two, _ := os.ReadFile(filepath.Join(dir, dataFile))
	if bytes.Equal(one, two) {
		t.Error("every write must use a fresh nonce and counter")
	}
	if bytes.Equal(one[:8], two[:8]) {
		t.Error("the counter must advance on every write")
	}
}

func TestPutThenFailedSaveRollsBackTheEntry(t *testing.T) {
	v, dir := newVault(t)
	mustInit(t, v)
	v.Put("k", []byte("old"))
	// make the next save fail: the data file goes back in time, so the counter check refuses the write
	old, _ := os.ReadFile(filepath.Join(dir, dataFile))
	v.Put("other", []byte("x"))
	os.WriteFile(filepath.Join(dir, dataFile), old, 0o600)
	if err := v.Put("k", []byte("new")); err == nil {
		t.Fatal("the save must fail")
	}
	if got, _ := v.Get("k"); string(got) != "old" {
		t.Errorf("a failed Put must leave the previous value in memory, got %q", got)
	}
	if err := v.Delete("k"); err == nil {
		t.Fatal("the save must fail")
	}
	if got, err := v.Get("k"); err != nil || string(got) != "old" {
		t.Errorf("a failed Delete must keep the entry: %q %v", got, err)
	}
	if err := v.Put("fresh", []byte("x")); err == nil {
		t.Fatal("the save must fail")
	}
	if _, err := v.Get("fresh"); !errors.Is(err, ErrNoEntry) {
		t.Errorf("a failed Put of a new key must not leave it behind: %v", err)
	}
}

func TestChangeRefusesNewWeakPassphraseWithoutTouchingTheHeader(t *testing.T) {
	v, dir := newVault(t)
	mustInit(t, v)
	before, _ := os.ReadFile(filepath.Join(dir, headerFile))
	for _, bad := range []string{"short", "", strings.Repeat("a", 20)} {
		if err := v.Change(goodPass, bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	after, _ := os.ReadFile(filepath.Join(dir, headerFile))
	if !bytes.Equal(before, after) {
		t.Error("a refused change must not rewrite the header")
	}
	if err := fast(New(dir)).Unlock(goodPass); err != nil {
		t.Errorf("the old passphrase must still work: %v", err)
	}
}

func TestInitWithWeakPassphraseCreatesNoFiles(t *testing.T) {
	v, dir := newVault(t)
	if err := v.Init("weak"); err == nil {
		t.Fatal("must be refused")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Errorf("a refused Init must leave the directory empty, found %d entries", len(ents))
	}
}

func TestDeriveKeyDependsOnTheVaultToo(t *testing.T) {
	a, _ := newVault(t)
	b, _ := newVault(t)
	mustInit(t, a)
	mustInit(t, b)
	ka, _ := a.DeriveKey("sessions")
	kb, _ := b.DeriveKey("sessions")
	if bytes.Equal(ka, kb) {
		t.Error("two vaults must not derive the same key for one purpose")
	}
}

func TestDigitsOnlyPassphraseIsRefusedEvenWhenLongAndVaried(t *testing.T) {
	if err := CheckPassphrase("1234567890123456789"); err == nil {
		t.Error("a bare run of digits must be refused")
	}
	if err := CheckPassphrase("1234567890123456a"); err != nil {
		t.Errorf("one letter among digits is enough: %v", err)
	}
}

func TestPassphraseLengthCountsCharactersNotBytes(t *testing.T) {
	fifteen := "春眠不觉晓处处闻啼鸟夜来风雨声"[:3*15]
	if utf8.RuneCountInString(fifteen) != 15 {
		t.Fatal("test string is wrong")
	}
	if err := CheckPassphrase(fifteen); err == nil {
		t.Error("15 characters of 3 bytes each are 45 bytes but still too short")
	}
}

func TestIdleTimeoutZeroNeverLocks(t *testing.T) {
	v, _ := newVault(t)
	mustInit(t, v)
	now := time.Now()
	v.now = func() time.Time { return now }
	v.SetIdleTimeout(0)
	now = now.Add(1000 * time.Hour)
	if v.State() != Unlocked {
		t.Error("a zero timeout means no auto-lock")
	}
}

func TestMissingDataFileIsCorruptionNotAnEmptyVault(t *testing.T) {
	v, dir := newVault(t)
	mustInit(t, v)
	v.Put("k", []byte("v"))
	v.Lock()
	if err := os.Remove(filepath.Join(dir, dataFile)); err != nil {
		t.Fatal(err)
	}
	// Opening an empty vault here would silently drop every secret and let the next write replace the evidence.
	if err := fast(New(dir)).Unlock(goodPass); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a vault whose data file vanished must refuse to open: %v", err)
	}
}

func TestTruncatedDataFileIsCorruption(t *testing.T) {
	v, dir := newVault(t)
	mustInit(t, v)
	path := filepath.Join(dir, dataFile)
	for _, n := range []int{0, 5, 8, 20} {
		b, _ := os.ReadFile(path)
		os.WriteFile(path, b[:n], 0o600)
		if err := fast(New(dir)).Unlock(goodPass); !errors.Is(err, ErrCorrupt) {
			t.Errorf("a data file cut to %d bytes must be corrupt: %v", n, err)
		}
		os.WriteFile(path, b, 0o600)
	}
}

func TestFailedInitLeavesNoDataFileBehind(t *testing.T) {
	v, dir := newVault(t)
	if err := os.MkdirAll(filepath.Join(dir, headerFile+".tmp"), 0o700); err != nil { // the header cannot be written
		t.Fatal(err)
	}
	if err := v.Init(goodPass); err == nil {
		t.Fatal("Init must fail when the header cannot be written")
	}
	if fileExists(filepath.Join(dir, dataFile)) {
		t.Error("a half-made vault must not leave its data file behind: the next Init would find a stray file and the vault would look half-initialised")
	}
	if v.State() == Unlocked {
		t.Error("a failed Init must not leave the vault unlocked")
	}
}

// The two seals bind the vault's id separately; these build the situations in which only one of the two can notice.

func TestWrappedKeyIsBoundToTheVaultID(t *testing.T) {
	v, dir := newVault(t)
	mustInit(t, v)
	raw, _ := os.ReadFile(filepath.Join(dir, headerFile))
	var h header
	json.Unmarshal(raw, &h)
	h.ID = append([]byte{}, h.ID...)
	h.ID[0] ^= 0xFF
	if _, err := unwrapMaster(&h, goodPass); err == nil {
		t.Error("the wrapped master key must not open under a different vault id")
	}
}

func TestDataFileIsBoundToTheVaultIDEvenWithTheSameMasterKey(t *testing.T) {
	a, dirA := newVault(t)
	mustInit(t, a)
	a.Put("k", []byte("from A"))
	a.mu.Lock()
	master := append([]byte{}, a.master...)
	a.mu.Unlock()
	// Vault B has the same master key and passphrase and a perfectly valid header of its own, but another id.
	dirB := filepath.Join(t.TempDir(), "vault")
	os.MkdirAll(dirB, 0o700)
	idB, _ := random(16)
	hB := &header{Version: formatVersion, ID: idB, KDF: a.kdf}
	if err := wrapMaster(hB, goodPass, master); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dirB, headerFile), mustJSON(hB), 0o600)
	data, _ := os.ReadFile(filepath.Join(dirA, dataFile))
	os.WriteFile(filepath.Join(dirB, dataFile), data, 0o600)
	if err := fast(New(dirB)).Unlock(goodPass); !errors.Is(err, ErrCorrupt) {
		t.Errorf("A's data file must not open in B even when the key and passphrase match: %v", err)
	}
}

// Every agent session starts its own login process, so several processes open one vault at once. A write by another
// process is progress and must be followed; a data file that went backwards is an old copy put back and stays refused.

func twoProcesses(t *testing.T) (*Vault, *Vault, string) {
	t.Helper()
	a, dir := newVault(t)
	mustInit(t, a)
	b := fast(New(dir))
	if err := b.Unlock(goodPass); err != nil {
		t.Fatal(err)
	}
	return a, b, dir
}

func TestAnotherProcessesWriteIsFollowed(t *testing.T) {
	a, b, _ := twoProcesses(t)
	if err := a.Put("from-a", []byte("1")); err != nil {
		t.Fatal(err)
	}
	if got, err := b.Get("from-a"); err != nil || string(got) != "1" {
		t.Fatalf("a read must see what another process wrote: %q %v", got, err)
	}
	if err := b.Put("from-b", []byte("2")); err != nil {
		t.Fatalf("a write after another process's write must succeed: %v", err)
	}
	if got, err := a.Get("from-b"); err != nil || string(got) != "2" {
		t.Fatalf("%q %v", got, err)
	}
	if got, _ := b.Get("from-a"); string(got) != "1" {
		t.Errorf("b's write must not drop a's entry: %q", got)
	}
}

func TestWritesFromTwoProcessesDoNotLoseEntries(t *testing.T) {
	a, b, dir := twoProcesses(t)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		for _, v := range []*Vault{a, b} {
			wg.Add(1)
			go func(v *Vault, i int) {
				defer wg.Done()
				k := fmt.Sprintf("%p-%d", v, i)
				if err := v.Put(k, []byte(k)); err != nil {
					t.Error(err)
				}
			}(v, i)
		}
	}
	wg.Wait()
	c := fast(New(dir))
	c.Unlock(goodPass)
	if n := len(c.Keys("")); n != 20 {
		t.Errorf("%d entries survived two processes writing at once, want 20", n)
	}
}

func TestDeleteSeesAnotherProcessesEntry(t *testing.T) {
	a, b, _ := twoProcesses(t)
	a.Put("shared", []byte("x"))
	if err := b.Delete("shared"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Get("shared"); !errors.Is(err, ErrNoEntry) {
		t.Errorf("an entry another process wrote must be deletable before it was ever read here: %v", err)
	}
}

func TestListSeesAnotherProcessesEntries(t *testing.T) {
	a, b, _ := twoProcesses(t)
	a.Put("session/x", []byte("1"))
	if keys := b.Keys("session/"); len(keys) != 1 {
		t.Errorf("Keys must follow other processes: %v", keys)
	}
}

func TestRollbackStaysRefusedAfterFollowingAnotherProcess(t *testing.T) {
	a, b, dir := twoProcesses(t)
	a.Put("k", []byte("v1"))
	old, _ := os.ReadFile(filepath.Join(dir, dataFile))
	a.Put("k", []byte("v2"))
	if got, _ := b.Get("k"); string(got) != "v2" { // b has now seen the newer write
		t.Fatalf("setup: %q", got)
	}
	os.WriteFile(filepath.Join(dir, dataFile), old, 0o600) // an attacker puts the old file back
	if err := b.Put("x", []byte("y")); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a data file that went backwards must be refused: %v", err)
	}
	if err := b.Delete("k"); !errors.Is(err, ErrCorrupt) {
		t.Errorf("also for deletes: %v", err)
	}
}

func TestReadIsNotBrokenByARolledBackFile(t *testing.T) {
	a, b, dir := twoProcesses(t)
	a.Put("k", []byte("v1"))
	old, _ := os.ReadFile(filepath.Join(dir, dataFile))
	a.Put("k", []byte("v2"))
	b.Get("k")
	os.WriteFile(filepath.Join(dir, dataFile), old, 0o600)
	if got, err := b.Get("k"); err != nil || string(got) != "v2" {
		t.Errorf("a read is served from memory and does not adopt an older file: %q %v", got, err)
	}
}

func TestFollowingRefusesAForgedNewerFile(t *testing.T) {
	a, b, dir := twoProcesses(t)
	a.Put("k", []byte("v"))
	path := filepath.Join(dir, dataFile)
	raw, _ := os.ReadFile(path)
	binary.BigEndian.PutUint64(raw[:8], binary.BigEndian.Uint64(raw[:8])+5)
	os.WriteFile(path, raw, 0o600)
	if err := b.Put("x", []byte("y")); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a file claiming a newer write without a valid seal must be refused: %v", err)
	}
	if _, err := b.Get("k"); err != nil && !errors.Is(err, ErrNoEntry) {
		t.Errorf("a read keeps serving what it has: %v", err)
	}
}

func TestLockedProcessNeedsNoSyncOnUnlock(t *testing.T) {
	a, b, _ := twoProcesses(t)
	b.Lock()
	a.Put("while-locked", []byte("1"))
	if err := b.Unlock(goodPass); err != nil {
		t.Fatal(err)
	}
	if got, _ := b.Get("while-locked"); string(got) != "1" {
		t.Errorf("unlocking loads the current file: %q", got)
	}
}

func TestSyncRefusesARollbackByItself(t *testing.T) {
	a, b, dir := twoProcesses(t)
	a.Put("k", []byte("v1"))
	old, _ := os.ReadFile(filepath.Join(dir, dataFile))
	a.Put("k", []byte("v2"))
	b.Get("k")
	os.WriteFile(filepath.Join(dir, dataFile), old, 0o600)
	b.mu.Lock()
	err := b.syncLocked()
	b.mu.Unlock()
	if !errors.Is(err, ErrCorrupt) {
		t.Errorf("syncLocked must refuse an older file on its own, not rely on the check inside the save: %v", err)
	}
}

func TestSyncAdoptsTheNewCounter(t *testing.T) {
	a, b, _ := twoProcesses(t)
	a.Put("k", []byte("v"))
	b.mu.Lock()
	err := b.syncLocked()
	counter := b.counter
	b.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	want := a.counter
	a.mu.Unlock()
	if counter != want {
		t.Errorf("after following, the counter is %d, want %d: the next write would otherwise be refused as a rollback", counter, want)
	}
}

func TestFollowingWipesTheOldEntriesFromMemory(t *testing.T) {
	a, b, _ := twoProcesses(t)
	b.Put("old", []byte("SECRET-VALUE"))
	b.mu.Lock()
	held := b.entries["old"] // the slice the vault holds right now
	b.mu.Unlock()
	a.Put("new", []byte("x")) // advances the file, so b's next sync replaces its entries
	b.mu.Lock()
	b.syncLocked()
	b.mu.Unlock()
	if !bytes.Equal(held, make([]byte, len(held))) {
		t.Errorf("entries that are replaced must be overwritten, not left for the garbage collector: %q", held)
	}
}

func TestPutNewRefusesToReplace(t *testing.T) {
	v, _ := newVault(t)
	mustInit(t, v)
	if err := v.PutNew("totp/link", []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := v.PutNew("totp/link", []byte("second")); !errors.Is(err, ErrExists) {
		t.Fatalf("a second PutNew must say the entry exists: %v", err)
	}
	if got, _ := v.Get("totp/link"); string(got) != "first" {
		t.Errorf("the existing value must be untouched: %q", got)
	}
	if err := v.Put("totp/link", []byte("replaced")); err != nil {
		t.Errorf("plain Put still replaces: %v", err)
	}
}

func TestPutNewSeesAnotherProcessesEntry(t *testing.T) {
	a, b, _ := twoProcesses(t)
	if err := a.PutNew("totp/seal", []byte("A")); err != nil {
		t.Fatal(err)
	}
	// b has not read anything yet: it must still learn that the entry exists, or two processes could both "create" it
	if err := b.PutNew("totp/seal", []byte("B")); !errors.Is(err, ErrExists) {
		t.Fatalf("PutNew must check against the current file, not this process's memory: %v", err)
	}
	if got, _ := a.Get("totp/seal"); string(got) != "A" {
		t.Errorf("%q", got)
	}
}

func TestPutNewIsAtomicBetweenProcesses(t *testing.T) {
	a, b, _ := twoProcesses(t)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i, v := range []*Vault{a, b} {
		wg.Add(1)
		go func(v *Vault, i int) {
			defer wg.Done()
			results <- v.PutNew("race", []byte{byte('A' + i)})
		}(v, i)
	}
	wg.Wait()
	close(results)
	ok, exists := 0, 0
	for err := range results {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrExists):
			exists++
		default:
			t.Errorf("unexpected: %v", err)
		}
	}
	if ok != 1 || exists != 1 {
		t.Errorf("exactly one creator may win: %d created, %d refused", ok, exists)
	}
}

func TestPutNewOnLockedVault(t *testing.T) {
	v, _ := newVault(t)
	mustInit(t, v)
	v.Lock()
	if err := v.PutNew("k", []byte("x")); !errors.Is(err, ErrLocked) {
		t.Errorf("%v", err)
	}
}

func TestPutNewCopiesItsInput(t *testing.T) {
	v, _ := newVault(t)
	mustInit(t, v)
	in := []byte("abc")
	v.PutNew("k", in)
	in[0] = 'Z'
	if got, _ := v.Get("k"); string(got) != "abc" {
		t.Errorf("%q", got)
	}
}

// The domain-separation labels are part of the file format: a vault written under one label does not open under another.
// A round trip cannot show that (both sides change together), so these tests build the three values by hand from the
// documented steps and require the vault to agree, byte for byte.

func TestTheWrappedKeyIsSealedUnderTheDocumentedHeaderLabel(t *testing.T) {
	v, dir := newVault(t)
	mustInit(t, v)
	raw, _ := os.ReadFile(filepath.Join(dir, headerFile))
	var h header
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	key := deriveWrapKey(goodPass, h.Salt, h.KDF)
	g, _ := gcm(key)
	aad := append([]byte("securl-vault-header-v1|"), h.ID...)
	master, err := g.Open(nil, h.Nonce, h.Wrapped, aad)
	if err != nil {
		t.Fatalf("the wrapped key must open under the documented additional data: %v", err)
	}
	if len(master) != 32 {
		t.Errorf("%d", len(master))
	}
}

func TestTheDataFileIsSealedUnderTheDocumentedDataLabel(t *testing.T) {
	v, dir := newVault(t)
	mustInit(t, v)
	v.Put("k", []byte("v"))
	v.mu.Lock()
	master := append([]byte{}, v.master...)
	id := append([]byte{}, v.hdr.ID...)
	v.mu.Unlock()
	raw, _ := os.ReadFile(filepath.Join(dir, dataFile))
	g, _ := gcm(master)
	counter := raw[:8]
	nonce := raw[8 : 8+g.NonceSize()]
	aad := append(append([]byte("securl-vault-data-v1|"), id...), counter...)
	if _, err := g.Open(nil, nonce, raw[8+g.NonceSize():], aad); err != nil {
		t.Fatalf("the data file must open under the documented additional data: %v", err)
	}
}

func TestDeriveKeyUsesTheDocumentedLabel(t *testing.T) {
	v, _ := newVault(t)
	mustInit(t, v)
	v.mu.Lock()
	master := append([]byte{}, v.master...)
	v.mu.Unlock()
	m := hmac.New(sha256.New, master)
	m.Write([]byte("securl-vault-derive-v1|sessions"))
	want := m.Sum(nil)
	got, err := v.DeriveKey("sessions")
	if err != nil || !bytes.Equal(got, want) {
		t.Errorf("the derived key must equal HMAC-SHA-256(master, \"securl-vault-derive-v1|sessions\"): %v", err)
	}
}
