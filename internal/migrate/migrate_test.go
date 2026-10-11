package migrate

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/totp"
	"github.com/LeafAI/securl/internal/vault"
)

const pass = "correct horse battery staple"

type fixture struct {
	dir   string // the config directory the old files live in
	v     *vault.Vault
	paths Paths
	link  []byte
	seal  []byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	v := vault.NewWithCost(filepath.Join(dir, "vault"), 1, 8, 1)
	if err := v.Init(pass); err != nil {
		t.Fatal(err)
	}
	return &fixture{dir: dir, v: v, paths: Paths{
		LinkSecret:  filepath.Join(dir, "totp", "link.secret"),
		SealSecret:  filepath.Join(dir, "totp", "seal.secret"),
		SessionsDir: filepath.Join(dir, "sessions"),
		KeysDir:     filepath.Join(dir, "keys"),
	}}
}

func (f *fixture) writeTOTP(t *testing.T) {
	t.Helper()
	f.link, _ = totp.NewSecret()
	f.seal, _ = totp.NewSecret()
	if err := totp.SaveSecret(f.paths.LinkSecret, f.link); err != nil {
		t.Fatal(err)
	}
	if err := totp.SaveSecret(f.paths.SealSecret, f.seal); err != nil {
		t.Fatal(err)
	}
}

type oldSession struct {
	Site       string            `json:"site"`
	Base       string            `json:"base"`
	Headers    map[string]string `json:"headers,omitempty"`
	Tokens     map[string]string `json:"tokens,omitempty"`
	ObtainedAt time.Time         `json:"obtained_at"`
}

// writeOldSessions writes sessions.enc and sessions.key exactly as the previous version did.
func (f *fixture) writeOldSessions(t *testing.T, list ...oldSession) {
	t.Helper()
	if err := os.MkdirAll(f.paths.SessionsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	rand.Read(key)
	blk, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(blk)
	plain, _ := json.Marshal(list)
	nonce := make([]byte, g.NonceSize())
	rand.Read(nonce)
	if err := os.WriteFile(filepath.Join(f.paths.SessionsDir, "sessions.key"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.paths.SessionsDir, "sessions.enc"), append(nonce, g.Seal(nil, nonce, plain, nil)...), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) writeOldKeys(t *testing.T) {
	t.Helper()
	os.MkdirAll(f.paths.KeysDir, 0o700)
	for _, n := range []string{"aaaa.asc", "aaaa.json", "bbbb.asc", "bbbb.json", ".lock"} {
		os.WriteFile(filepath.Join(f.paths.KeysDir, n), []byte("-----BEGIN PGP PRIVATE KEY BLOCK-----\nOLD\n"), 0o600)
	}
}

func TestMovesTOTPSecretsIntoTheVaultAndRemovesTheFiles(t *testing.T) {
	f := newFixture(t)
	f.writeTOTP(t)
	rep, err := Run(f.v, f.paths)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][]byte{"totp/link": f.link, "totp/seal": f.seal} {
		raw, err := f.v.Get(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, err := totp.ParseSecret(string(raw))
		if err != nil || string(got) != string(want) {
			t.Errorf("%s was not carried over unchanged: %v", name, err)
		}
	}
	if exists(f.paths.LinkSecret) || exists(f.paths.SealSecret) {
		t.Error("the plaintext files must be gone once the vault has the secrets")
	}
	if rep.TOTP != 2 {
		t.Errorf("report: %+v", rep)
	}
}

func TestSecretIsVerifiedInTheVaultBeforeTheFileGoes(t *testing.T) {
	f := newFixture(t)
	f.writeTOTP(t)
	// a vault that accepts the write and then loses it: the file must stay
	lossy := &lossyVault{Vault: f.v}
	rep, err := Run(lossy, f.paths)
	if err != nil {
		t.Fatalf("one item that cannot be stored must not abort the run: %v", err)
	}
	if !exists(f.paths.LinkSecret) || !exists(f.paths.SealSecret) {
		t.Fatal("a file must never be deleted before its content has been read back from the vault")
	}
	if rep.TOTP != 0 || len(rep.Skipped) != 2 {
		t.Errorf("both must be reported as kept, and none as moved: %+v", rep)
	}
}

type lossyVault struct{ *vault.Vault }

func (l *lossyVault) PutNew(key string, value []byte) error { return nil } // pretends to store

func TestAnExistingVaultSecretIsNeverReplaced(t *testing.T) {
	f := newFixture(t)
	f.writeTOTP(t)
	mine, _ := totp.NewSecret()
	if err := f.v.Put("totp/link", []byte(totp.FormatSecret(mine))); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(f.v, f.paths)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := f.v.Get("totp/link")
	if string(raw) != totp.FormatSecret(mine) {
		t.Fatal("a secret already in the vault was replaced by the file's: the person's authenticator would stop working")
	}
	if !exists(f.paths.LinkSecret) {
		t.Error("a file whose secret differs from the vault's must be kept, not deleted: it may be the one that is registered")
	}
	if len(rep.Conflicts) != 1 || !strings.Contains(rep.Conflicts[0], "link") {
		t.Errorf("the conflict must be reported: %+v", rep)
	}
	if !exists(f.paths.SealSecret) == false {
		// the other factor had no conflict and is moved
	}
	if raw, err := f.v.Get("totp/seal"); err != nil || string(raw) != totp.FormatSecret(f.seal) {
		t.Errorf("the seal secret has no conflict and must still be moved: %v", err)
	}
}

func TestAnIdenticalSecretInBothPlacesIsJustTidied(t *testing.T) {
	f := newFixture(t)
	f.writeTOTP(t)
	f.v.Put("totp/link", []byte(totp.FormatSecret(f.link)))
	rep, err := Run(f.v, f.paths)
	if err != nil {
		t.Fatal(err)
	}
	if exists(f.paths.LinkSecret) {
		t.Error("the same secret already in the vault: the leftover file can go")
	}
	if len(rep.Conflicts) != 0 {
		t.Errorf("identical is not a conflict: %+v", rep)
	}
}

func TestRunIsIdempotent(t *testing.T) {
	f := newFixture(t)
	f.writeTOTP(t)
	f.writeOldKeys(t)
	f.writeOldSessions(t, oldSession{Site: "gitlab", Base: "https://g.example", Tokens: map[string]string{"t": "1"}, ObtainedAt: time.Now()})
	if _, err := Run(f.v, f.paths); err != nil {
		t.Fatal(err)
	}
	before := f.v.Keys("")
	rep, err := Run(f.v, f.paths)
	if err != nil {
		t.Fatalf("a second run must be harmless: %v", err)
	}
	if rep.Total() != 0 {
		t.Errorf("nothing is left to do: %+v", rep)
	}
	if after := f.v.Keys(""); len(after) != len(before) {
		t.Errorf("entries changed on a second run: %v -> %v", before, after)
	}
}

func TestNothingToMigrateIsFine(t *testing.T) {
	f := newFixture(t)
	rep, err := Run(f.v, f.paths)
	if err != nil || rep.Total() != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
}

func TestOldSessionsAreDecryptedAndStoredInTheVault(t *testing.T) {
	f := newFixture(t)
	f.writeOldSessions(t,
		oldSession{Site: "gitlab", Base: "https://g.example", Headers: map[string]string{"Authorization": "Bearer OLD-TOKEN"}, Tokens: map[string]string{"t": "1"}, ObtainedAt: time.Unix(1700000000, 0)},
		oldSession{Site: "jenkins", Base: "https://j.example", ObtainedAt: time.Unix(1700000001, 0)})
	rep, err := Run(f.v, f.paths)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Sessions != 2 {
		t.Errorf("%+v", rep)
	}
	raw, err := f.v.Get("session/https://g.example")
	if err != nil || !strings.Contains(string(raw), "OLD-TOKEN") || !strings.Contains(string(raw), `"site":"gitlab"`) {
		t.Fatalf("the session must arrive intact: %q %v", raw, err)
	}
	if exists(filepath.Join(f.paths.SessionsDir, "sessions.enc")) || exists(filepath.Join(f.paths.SessionsDir, "sessions.key")) {
		t.Error("the old session files must be removed: the key sat next to the data")
	}
}

func TestACorruptOldSessionFileIsKeptAndReported(t *testing.T) {
	f := newFixture(t)
	f.writeOldSessions(t, oldSession{Site: "gitlab", Base: "https://g.example"})
	os.WriteFile(filepath.Join(f.paths.SessionsDir, "sessions.enc"), []byte("garbage that does not decrypt"), 0o600)
	rep, err := Run(f.v, f.paths)
	if err != nil {
		t.Fatalf("an unreadable old session file must not abort the migration of everything else: %v", err)
	}
	if !exists(filepath.Join(f.paths.SessionsDir, "sessions.enc")) {
		t.Error("a file that could not be read must not be deleted; it is not ours to destroy")
	}
	if len(rep.Skipped) == 0 {
		t.Errorf("the problem must be reported: %+v", rep)
	}
}

func TestSessionFilesWithoutAKeyAreKept(t *testing.T) {
	f := newFixture(t)
	f.writeOldSessions(t, oldSession{Site: "gitlab", Base: "https://g.example"})
	os.Remove(filepath.Join(f.paths.SessionsDir, "sessions.key"))
	rep, _ := Run(f.v, f.paths)
	if !exists(filepath.Join(f.paths.SessionsDir, "sessions.enc")) {
		t.Error("with no key the data cannot be read: keep it")
	}
	if len(rep.Skipped) == 0 {
		t.Errorf("%+v", rep)
	}
}

func TestAnExistingVaultSessionWinsOverAnOldOne(t *testing.T) {
	f := newFixture(t)
	f.v.Put("session/https://g.example", []byte(`{"site":"gitlab","base":"https://g.example","tokens":{"t":"NEWER"}}`))
	f.writeOldSessions(t, oldSession{Site: "gitlab", Base: "https://g.example", Tokens: map[string]string{"t": "OLDER"}})
	if _, err := Run(f.v, f.paths); err != nil {
		t.Fatal(err)
	}
	raw, _ := f.v.Get("session/https://g.example")
	if !strings.Contains(string(raw), "NEWER") {
		t.Errorf("a session already in the vault is newer than anything in an old file: %s", raw)
	}
}

func TestOldTransportKeysAreSimplyRemoved(t *testing.T) {
	f := newFixture(t)
	f.writeOldKeys(t)
	rep, err := Run(f.v, f.paths)
	if err != nil {
		t.Fatal(err)
	}
	if exists(f.paths.KeysDir) {
		ents, _ := os.ReadDir(f.paths.KeysDir)
		t.Errorf("private key files must not stay on disk: %d left", len(ents))
	}
	if rep.Keys != 4 {
		t.Errorf("the four key files are counted (the lock file is not): %+v", rep)
	}
}

func TestOnlyOurOwnFilesInTheKeyDirectoryAreRemoved(t *testing.T) {
	f := newFixture(t)
	f.writeOldKeys(t)
	os.WriteFile(filepath.Join(f.paths.KeysDir, "notes.txt"), []byte("mine"), 0o600)
	os.MkdirAll(filepath.Join(f.paths.KeysDir, "sub"), 0o700)
	Run(f.v, f.paths)
	if !exists(filepath.Join(f.paths.KeysDir, "notes.txt")) || !exists(filepath.Join(f.paths.KeysDir, "sub")) {
		t.Error("a directory that is shared with the person's own files must keep them: remove only what login made")
	}
}

func TestFilesAreOverwrittenBeforeTheyAreRemoved(t *testing.T) {
	f := newFixture(t)
	f.writeTOTP(t)
	var seen []byte
	remove = func(p string) error { // observe what is on disk at the moment of removal
		b, _ := os.ReadFile(p)
		seen = append(seen, b...)
		return os.Remove(p)
	}
	defer func() { remove = os.Remove }()
	Run(f.v, f.paths)
	if len(seen) == 0 {
		t.Fatal("test setup: nothing was removed")
	}
	if strings.Contains(string(seen), totp.FormatSecret(f.link)) || strings.Contains(string(seen), totp.FormatSecret(f.seal)) {
		t.Error("the secret was still readable in the file when it was removed: overwrite it first")
	}
}

func TestExposedLegacyFilesAreReportedForRotation(t *testing.T) {
	f := newFixture(t)
	f.writeTOTP(t)
	os.Chmod(f.paths.LinkSecret, 0o644)
	rep, err := Run(f.v, f.paths)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Exposed) != 1 || !strings.Contains(rep.Exposed[0], "link") {
		t.Errorf("a secret that other users could read is compromised, and the person must be told: %+v", rep)
	}
	if raw, err := f.v.Get("totp/link"); err != nil || string(raw) != totp.FormatSecret(f.link) {
		t.Errorf("it is still moved (the alternative is leaving it exposed): %v", err)
	}
}

func TestAnUnreadableTOTPFileIsKeptAndReported(t *testing.T) {
	f := newFixture(t)
	os.MkdirAll(filepath.Dir(f.paths.LinkSecret), 0o700)
	os.WriteFile(f.paths.LinkSecret, []byte("not a base32 secret !!!"), 0o600)
	rep, err := Run(f.v, f.paths)
	if err != nil {
		t.Fatal(err)
	}
	if !exists(f.paths.LinkSecret) {
		t.Error("a file that is not a valid secret is kept")
	}
	if len(rep.Skipped) == 0 {
		t.Errorf("%+v", rep)
	}
	if _, err := f.v.Get("totp/link"); !errors.Is(err, vault.ErrNoEntry) {
		t.Errorf("garbage must not be stored as a secret: %v", err)
	}
}

func TestMigrationNeedsAnOpenVault(t *testing.T) {
	f := newFixture(t)
	f.writeTOTP(t)
	f.v.Lock()
	if _, err := Run(f.v, f.paths); !errors.Is(err, vault.ErrLocked) {
		t.Fatalf("%v", err)
	}
	if !exists(f.paths.LinkSecret) {
		t.Error("a refused migration must not touch the files")
	}
}

func TestReportNeverContainsASecret(t *testing.T) {
	f := newFixture(t)
	f.writeTOTP(t)
	os.Chmod(f.paths.LinkSecret, 0o644)
	f.writeOldSessions(t, oldSession{Site: "gitlab", Base: "https://g.example", Headers: map[string]string{"Authorization": "Bearer SUPERSECRET"}})
	rep, _ := Run(f.v, f.paths)
	text := rep.String()
	for _, secret := range []string{totp.FormatSecret(f.link), totp.FormatSecret(f.seal), "SUPERSECRET"} {
		if strings.Contains(text, secret) {
			t.Errorf("the report leaks %q:\n%s", secret, text)
		}
	}
}

func TestPartialFailureLeavesEveryFileEitherMovedOrIntact(t *testing.T) {
	f := newFixture(t)
	f.writeTOTP(t)
	// the seal secret cannot be stored (the vault refuses that one name)
	picky := &pickyVault{Vault: f.v, refuse: "totp/seal"}
	rep, err := Run(picky, f.paths)
	if err == nil && len(rep.Skipped) == 0 {
		t.Fatal("a failure must be reported")
	}
	if exists(f.paths.LinkSecret) {
		t.Error("the link secret was stored and verified: its file can go")
	}
	if !exists(f.paths.SealSecret) {
		t.Error("the seal secret could not be stored: its file must stay")
	}
	if raw, err := f.v.Get("totp/link"); err != nil || string(raw) != totp.FormatSecret(f.link) {
		t.Errorf("%v", err)
	}
}

type pickyVault struct {
	*vault.Vault
	refuse string
}

func (p *pickyVault) PutNew(key string, value []byte) error {
	if key == p.refuse {
		return errors.New("disk full")
	}
	return p.Vault.PutNew(key, value)
}

// A secret the vault will not store must stay in its file, and must not be counted as moved. The file may be the only
// copy of something registered in an authenticator.
func TestAFailedStoreKeepsTheFileAndCountsNothing(t *testing.T) {
	f := newFixture(t)
	f.writeTOTP(t)
	picky := &pickyVault{Vault: f.v, refuse: "totp/seal"}
	rep, _ := Run(picky, f.paths)
	if !exists(f.paths.SealSecret) {
		t.Fatal("the secret could not be stored: its file is all that is left of it")
	}
	if rep.TOTP != 1 {
		t.Errorf("one secret moved, one not: %+v", rep)
	}
	if len(rep.Skipped) != 1 || !strings.Contains(rep.Skipped[0], "seal") || !strings.Contains(rep.Skipped[0], "disk full") {
		t.Errorf("the reason must be reported: %+v", rep.Skipped)
	}
	if _, err := f.v.Get("totp/seal"); !errors.Is(err, vault.ErrNoEntry) {
		t.Errorf("nothing was stored: %v", err)
	}
}

func TestAnOldSessionTheVaultCannotStoreKeepsTheOldFiles(t *testing.T) {
	f := newFixture(t)
	f.writeOldSessions(t,
		oldSession{Site: "gitlab", Base: "https://ok.example"},
		oldSession{Site: "jenkins", Base: "https://bad.example"})
	picky := &pickyVault{Vault: f.v, refuse: "session/https://bad.example"}
	rep, _ := Run(picky, f.paths)
	if !exists(filepath.Join(f.paths.SessionsDir, "sessions.enc")) || !exists(filepath.Join(f.paths.SessionsDir, "sessions.key")) {
		t.Fatal("one session could not be stored: the old files are the only copy of it and must stay (with their key)")
	}
	if len(rep.Skipped) == 0 || !strings.Contains(strings.Join(rep.Skipped, " "), "bad.example") {
		t.Errorf("%+v", rep)
	}
}

// A session that is already in the vault is newer than anything in an old file: the old one is dropped with its
// file, nothing is overwritten, and it is not counted as moved.
func TestAnExistingSessionIsNotOverwrittenNotCountedAndTheOldFileGoes(t *testing.T) {
	f := newFixture(t)
	f.v.Put("session/https://g.example", []byte(`{"site":"gitlab","base":"https://g.example","tokens":{"t":"NEWER"}}`))
	f.writeOldSessions(t,
		oldSession{Site: "gitlab", Base: "https://g.example", Tokens: map[string]string{"t": "OLDER"}},
		oldSession{Site: "jenkins", Base: "https://only-old.example"})
	rep, err := Run(f.v, f.paths)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Sessions != 1 {
		t.Errorf("only the session that was not in the vault counts as moved: %+v", rep)
	}
	if exists(filepath.Join(f.paths.SessionsDir, "sessions.enc")) {
		t.Error("everything in the old file is now either moved or superseded: it can go")
	}
	if _, err := f.v.Get("session/https://only-old.example"); err != nil {
		t.Errorf("%v", err)
	}
}

func TestAnOldKeyOfTheWrongSizeIsNotUsed(t *testing.T) {
	f := newFixture(t)
	f.writeOldSessions(t, oldSession{Site: "gitlab", Base: "https://g.example"})
	good, _ := os.ReadFile(filepath.Join(f.paths.SessionsDir, "sessions.key"))
	// 32 bytes is the only valid size; a 33-byte file whose first 32 bytes are the real key must not be accepted
	os.WriteFile(filepath.Join(f.paths.SessionsDir, "sessions.key"), append(append([]byte{}, good...), 'x'), 0o600)
	rep, _ := Run(f.v, f.paths)
	if rep.Sessions != 0 || len(rep.Skipped) == 0 {
		t.Errorf("a key file that is not exactly a key is refused: %+v", rep)
	}
	if !exists(filepath.Join(f.paths.SessionsDir, "sessions.enc")) {
		t.Error("and the data stays")
	}
}

func TestSubdirectoriesOfTheKeyDirectoryAreLeftAlone(t *testing.T) {
	f := newFixture(t)
	os.MkdirAll(filepath.Join(f.paths.KeysDir, "aaaa.asc"), 0o700) // a directory that happens to carry a key file's name
	os.WriteFile(filepath.Join(f.paths.KeysDir, "aaaa.asc", "inside"), []byte("x"), 0o600)
	rep, err := Run(f.v, f.paths)
	if err != nil {
		t.Fatal(err)
	}
	if !exists(filepath.Join(f.paths.KeysDir, "aaaa.asc", "inside")) {
		t.Error("a directory is never one of login's key files")
	}
	if rep.Keys != 0 {
		t.Errorf("%+v", rep)
	}
}

func TestOnlyKeyFileNamesAreRecognised(t *testing.T) {
	for name, want := range map[string]bool{
		"0123456789abcdef.asc": true, "ab.json": true, "deadbeefdeadbeef.json": true,
		"notes.asc": false, "ABCDEF.asc": false, "aaaa.txt": false, "aaaa": false, ".asc": false, "aaaa.asc.bak": false, "aa.bb.asc": false,
	} {
		if got := isKeyFile(name); got != want {
			t.Errorf("isKeyFile(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestAnEmptyKeyDirectoryIsRemovedButNotOneWithOtherFiles(t *testing.T) {
	f := newFixture(t)
	f.writeOldKeys(t)
	Run(f.v, f.paths)
	if exists(f.paths.KeysDir) {
		t.Error("an emptied key directory is tidied away")
	}
}

func TestMigrationDoesNotCrashOnMissingDirectories(t *testing.T) {
	f := newFixture(t)
	f.paths.KeysDir, f.paths.SessionsDir = filepath.Join(f.dir, "nope1"), filepath.Join(f.dir, "nope2")
	if _, err := Run(f.v, f.paths); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(f.v, Paths{}); err != nil {
		t.Fatalf("empty paths mean nothing to do: %v", err)
	}
}

// A vault that reads back something other than what was written must not cost the person their only copy.
func TestAReadBackThatDiffersKeepsTheFile(t *testing.T) {
	f := newFixture(t)
	f.writeTOTP(t)
	other, _ := totp.NewSecret()
	garbled := &garbledVault{Vault: f.v, reply: []byte(totp.FormatSecret(other))}
	rep, err := Run(garbled, f.paths)
	if err != nil {
		t.Fatal(err)
	}
	if !exists(f.paths.LinkSecret) || !exists(f.paths.SealSecret) {
		t.Fatal("the vault returned a different secret than was stored: the files are the only trustworthy copy and must stay")
	}
	if rep.TOTP != 0 {
		t.Errorf("nothing was verified, so nothing is moved: %+v", rep)
	}
}

// garbledVault stores faithfully but reads back a fixed, different value.
type garbledVault struct {
	*vault.Vault
	reply []byte
}

func (g *garbledVault) Get(key string) ([]byte, error) {
	if strings.HasPrefix(key, "totp/") {
		return g.reply, nil
	}
	return g.Vault.Get(key)
}

func (g *garbledVault) PutNew(key string, value []byte) error { return g.Vault.PutNew(key, value) }

// Only a key the previous version could have made (exactly 32 bytes, AES-256) is accepted. AES would also take 16 or 24
// bytes, and data under such a key is not data this program wrote.
func TestOnlyA256BitOldKeyIsAccepted(t *testing.T) {
	f := newFixture(t)
	os.MkdirAll(f.paths.SessionsDir, 0o700)
	key := make([]byte, 16)
	rand.Read(key)
	blk, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(blk)
	plain, _ := json.Marshal([]oldSession{{Site: "gitlab", Base: "https://g.example"}})
	nonce := make([]byte, g.NonceSize())
	rand.Read(nonce)
	os.WriteFile(filepath.Join(f.paths.SessionsDir, "sessions.key"), key, 0o600)
	os.WriteFile(filepath.Join(f.paths.SessionsDir, "sessions.enc"), append(nonce, g.Seal(nil, nonce, plain, nil)...), 0o600)
	rep, _ := Run(f.v, f.paths)
	if rep.Sessions != 0 || len(rep.Skipped) == 0 {
		t.Errorf("an AES-128 key is not ours: %+v", rep)
	}
	if _, err := f.v.Get("session/https://g.example"); !errors.Is(err, vault.ErrNoEntry) {
		t.Errorf("nothing from such a file is stored: %v", err)
	}
}
