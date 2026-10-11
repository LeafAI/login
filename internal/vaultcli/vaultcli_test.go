package vaultcli

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/totp"
	"github.com/LeafAI/securl/internal/vault"
)

const good = "correct horse battery staple"

type rig struct {
	dir     string
	cfgPath string
	cfg     *config.Config
	out     bytes.Buffer
	err     bytes.Buffer
}

func newRig(t *testing.T) *rig {
	t.Helper()
	dir := t.TempDir()
	r := &rig{dir: dir, cfgPath: filepath.Join(dir, "config.yaml")}
	cfg, err := config.Load(r.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	r.cfg = cfg
	return r
}

func (r *rig) vault() *vault.Vault { return vault.NewWithCost(r.cfg.Vault.Dir, 1, 8, 1) }

// run executes a command with the given typed lines (passphrases are read from the same lines).
func (r *rig) run(t *testing.T, lines string, args ...string) int {
	t.Helper()
	r.out.Reset()
	r.err.Reset()
	env := Env{Config: r.cfg, ConfigPath: r.cfgPath, Vault: r.vault(), In: strings.NewReader(lines), Out: &r.out, Err: &r.err}
	return Run(args, env)
}

func TestInitCreatesTheVaultAndNeverEchoesThePassphrase(t *testing.T) {
	r := newRig(t)
	if code := r.run(t, good+"\n"+good+"\n", "init"); code != 0 {
		t.Fatalf("exit %d: %s%s", code, r.out.String(), r.err.String())
	}
	if r.vault().State() != vault.Locked {
		t.Error("the CLI leaves the vault shut when it ends: every process has to open it itself")
	}
	if err := r.vault().Unlock(good); err != nil {
		t.Errorf("the vault must open with the passphrase that was typed: %v", err)
	}
	if strings.Contains(r.out.String()+r.err.String(), good) {
		t.Error("the passphrase must never be printed")
	}
}

func TestInitRefusesAWeakPassphraseAndAsksAgain(t *testing.T) {
	r := newRig(t)
	if code := r.run(t, "short\nsix\nstill short\n", "init"); code == 0 {
		t.Fatal("three weak passphrases in a row must end in failure")
	}
	if r.vault().State() != vault.NotInitialized {
		t.Error("nothing may be created")
	}
	if !strings.Contains(r.err.String(), "16") {
		t.Errorf("the refusal must say the minimum: %q", r.err.String())
	}
	// a weak one followed by a good one succeeds
	r2 := newRig(t)
	if code := r2.run(t, "short\n"+good+"\n"+good+"\n", "init"); code != 0 {
		t.Fatalf("a good passphrase after a weak one: exit %d: %s", code, r2.err.String())
	}
}

func TestInitNeedsTheSamePassphraseTwice(t *testing.T) {
	r := newRig(t)
	if code := r.run(t, good+"\n"+good+"x\n"+good+"\n"+good+"\n", "init"); code != 0 {
		t.Fatalf("a typo in the confirmation is asked again: exit %d: %s", code, r.err.String())
	}
	r2 := newRig(t)
	if code := r2.run(t, good+"\nnope nope nope nope\n"+good+"\nxxxxxxxxxxxxxxxxxxxx\n"+good+"\nyyyyyyyyyyyyyyyyyyyyyy\n", "init"); code == 0 {
		t.Fatal("three mismatches must fail")
	}
	if r2.vault().State() != vault.NotInitialized {
		t.Error("nothing may be created when the confirmation never matched")
	}
}

func TestInitRefusesWhenAVaultExists(t *testing.T) {
	r := newRig(t)
	r.run(t, good+"\n"+good+"\n", "init")
	if code := r.run(t, "another long passphrase here\nanother long passphrase here\n", "init"); code == 0 {
		t.Fatal("init must not replace an existing vault")
	}
	if !strings.Contains(r.err.String(), "already") {
		t.Errorf("%q", r.err.String())
	}
	if err := r.vault().Unlock(good); err != nil {
		t.Errorf("the original passphrase must still work: %v", err)
	}
}

func TestInitMovesWhatEarlierVersionsKeptInFiles(t *testing.T) {
	r := newRig(t)
	link, _ := totp.NewSecret()
	if err := totp.SaveSecret(r.cfg.Security.LinkTOTP.SecretFile, link); err != nil {
		t.Fatal(err)
	}
	if code := r.run(t, good+"\n"+good+"\n", "init"); code != 0 {
		t.Fatalf("exit %d: %s", code, r.err.String())
	}
	v := r.vault()
	if err := v.Unlock(good); err != nil {
		t.Fatal(err)
	}
	if raw, err := v.Get(config.LinkSecretName); err != nil || string(raw) != totp.FormatSecret(link) {
		t.Fatalf("the TOTP secret must be in the vault, unchanged: %v", err)
	}
	if _, err := os.Stat(r.cfg.Security.LinkTOTP.SecretFile); err == nil {
		t.Error("and the plaintext file must be gone")
	}
	if !strings.Contains(r.out.String(), "1 TOTP secret") {
		t.Errorf("init should say what it moved:\n%s", r.out.String())
	}
}

func TestStatusNeverNeedsAPassphrase(t *testing.T) {
	r := newRig(t)
	if code := r.run(t, "", "status"); code != 0 || !strings.Contains(r.out.String(), "not initialized") {
		t.Fatalf("%d %q", code, r.out.String())
	}
	r.run(t, good+"\n"+good+"\n", "init")
	if code := r.run(t, "", "status"); code != 0 || !strings.Contains(r.out.String(), "locked") {
		t.Fatalf("%d %q", code, r.out.String())
	}
	if strings.Contains(r.out.String(), r.cfg.Vault.Dir+"/data") {
		t.Error("status must not list internals")
	}
}

func TestPasswdChangesThePassphrase(t *testing.T) {
	r := newRig(t)
	r.run(t, good+"\n"+good+"\n", "init")
	next := "a completely different passphrase"
	if code := r.run(t, good+"\n"+next+"\n"+next+"\n", "passwd"); code != 0 {
		t.Fatalf("exit %d: %s", code, r.err.String())
	}
	v := r.vault()
	if err := v.Unlock(good); err == nil {
		t.Error("the old passphrase must stop working")
	}
	if err := v.Unlock(next); err != nil {
		t.Errorf("the new passphrase must work: %v", err)
	}
	if strings.Contains(r.out.String()+r.err.String(), next) || strings.Contains(r.out.String()+r.err.String(), good) {
		t.Error("no passphrase may be printed")
	}
}

func TestPasswdChecksTheOldPassphraseAndTheNewOne(t *testing.T) {
	r := newRig(t)
	r.run(t, good+"\n"+good+"\n", "init")
	if code := r.run(t, "wrong wrong wrong wrong\n"+"a completely different passphrase\n"+"a completely different passphrase\n", "passwd"); code == 0 {
		t.Fatal("the old passphrase must be right")
	}
	if code := r.run(t, good+"\nshort\nshort\nshort\n", "passwd"); code == 0 {
		t.Fatal("a weak new passphrase must be refused")
	}
	if err := r.vault().Unlock(good); err != nil {
		t.Errorf("a refused change must leave the vault as it was: %v", err)
	}
}

func TestPasswdOnAMissingVault(t *testing.T) {
	r := newRig(t)
	if code := r.run(t, good+"\n"+good+"\n"+good+"\n", "passwd"); code == 0 {
		t.Fatal("there is nothing to change")
	}
	if !strings.Contains(r.err.String(), "vault init") {
		t.Errorf("it should say how to make one: %q", r.err.String())
	}
}

func TestUnknownCommandsAndUsage(t *testing.T) {
	r := newRig(t)
	for _, args := range [][]string{{}, {"bogus"}, {"unlock"}, {"lock"}} {
		if code := r.run(t, "", args...); code == 0 {
			t.Errorf("%v succeeded", args)
		}
	}
	// There is deliberately no unlock/lock command: another process's vault cannot be opened from here.
	r.run(t, "", "unlock")
	if !strings.Contains(r.err.String(), "vault_unlock") && !strings.Contains(r.err.String(), "DingTalk") {
		t.Errorf("a person who types `securl vault unlock` must be told how a running server is opened: %q", r.err.String())
	}
}

func TestNoInputIsAnErrorNotAHang(t *testing.T) {
	r := newRig(t)
	if code := r.run(t, "", "init"); code == 0 {
		t.Fatal("init with no input must fail")
	}
	if r.vault().State() != vault.NotInitialized {
		t.Error("nothing created")
	}
}

func TestPassphraseWithSurroundingSpacesIsKeptExactly(t *testing.T) {
	r := newRig(t)
	pass := "  spaces matter in a passphrase  "
	if code := r.run(t, pass+"\n"+pass+"\n", "init"); code != 0 {
		t.Fatalf("%s", r.err.String())
	}
	if err := r.vault().Unlock(pass); err != nil {
		t.Errorf("a passphrase must be used exactly as typed, spaces included: %v", err)
	}
	if err := r.vault().Unlock(strings.TrimSpace(pass)); err == nil {
		t.Error("trimming would silently change the passphrase")
	}
}

// endless answers forever, so a loop that never gives up would never end.
type endless struct{ line string }

func (e endless) Read(p []byte) (int, error) {
	return copy(p, strings.Repeat(e.line+"\n", 1+len(p)/(len(e.line)+1))[:len(p)]), nil
}

func TestAskingGivesUpAfterThreeTriesEvenWithEndlessInput(t *testing.T) {
	r := newRig(t)
	done := make(chan int, 1)
	go func() {
		env := Env{Config: r.cfg, ConfigPath: r.cfgPath, Vault: r.vault(), In: endless{"weak"}, Out: &r.out, Err: &r.err}
		done <- Run([]string{"init"}, env)
	}()
	select {
	case code := <-done:
		if code == 0 {
			t.Error("a passphrase that is always weak must fail")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the prompt never gave up")
	}
	refusals := 0
	for _, line := range strings.Split(r.err.String(), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "! ") && strings.Contains(line, "too weak") {
			refusals++
		}
	}
	if refusals != maxAttempts {
		t.Errorf("exactly %d attempts are allowed, saw %d refusals", maxAttempts, refusals)
	}
}

func TestInitSaysThatAVaultExistsBeforeAskingForAnything(t *testing.T) {
	r := newRig(t)
	r.run(t, good+"\n"+good+"\n", "init")
	if code := r.run(t, "", "init"); code == 0 {
		t.Fatal("init on an existing vault must fail")
	}
	if strings.Contains(r.out.String(), "passphrase:") {
		t.Errorf("it must not ask for a new passphrase it will not use:\n%s", r.out.String())
	}
	if !strings.Contains(r.err.String(), "already initialized") || !strings.Contains(r.err.String(), "passwd") {
		t.Errorf("it should say why and what to do instead: %q", r.err.String())
	}
}

func TestTheVaultIsShutWhenInitEnds(t *testing.T) {
	r := newRig(t)
	v := r.vault()
	env := Env{Config: r.cfg, ConfigPath: r.cfgPath, Vault: v, In: strings.NewReader(good + "\n" + good + "\n"), Out: &r.out, Err: &r.err}
	if code := Run([]string{"init"}, env); code != 0 {
		t.Fatal(r.err.String())
	}
	if v.State() != vault.Locked {
		t.Errorf("the key of the vault must not stay in memory once the command is done: %v", v.State())
	}
}

func TestTheVaultIsShutWhenPasswdEnds(t *testing.T) {
	r := newRig(t)
	r.run(t, good+"\n"+good+"\n", "init")
	v := r.vault()
	next := "a completely different passphrase"
	env := Env{Config: r.cfg, ConfigPath: r.cfgPath, Vault: v, In: strings.NewReader(good + "\n" + next + "\n" + next + "\n"), Out: &r.out, Err: &r.err}
	if code := Run([]string{"passwd"}, env); code != 0 {
		t.Fatal(r.err.String())
	}
	if v.State() != vault.Locked {
		t.Errorf("%v", v.State())
	}
	// and also when the change is refused
	env = Env{Config: r.cfg, ConfigPath: r.cfgPath, Vault: v, In: strings.NewReader(next + "\nshort\nshort\nshort\n"), Out: &r.out, Err: &r.err}
	Run([]string{"passwd"}, env)
	if v.State() != vault.Locked {
		t.Errorf("a refused change must also leave it shut: %v", v.State())
	}
}

func TestPasswdWithTheWrongOldPassphraseDoesNotEvenAskForANewOne(t *testing.T) {
	r := newRig(t)
	r.run(t, good+"\n"+good+"\n", "init")
	if code := r.run(t, "this is not the passphrase\n", "passwd"); code == 0 {
		t.Fatal("must fail")
	}
	if strings.Contains(r.out.String(), "New vault passphrase") {
		t.Errorf("asking for a new passphrase after a wrong old one lets anyone at the keyboard probe:\n%s", r.out.String())
	}
	if !strings.Contains(r.err.String(), "wrong") {
		t.Errorf("%q", r.err.String())
	}
}

func TestPasswdOnAMissingVaultDoesNotAskForAnything(t *testing.T) {
	r := newRig(t)
	r.run(t, "", "passwd")
	if strings.Contains(r.out.String(), "passphrase:") {
		t.Errorf("there is no vault to ask about:\n%s", r.out.String())
	}
}

func TestNothingTypedIsEverPrinted(t *testing.T) {
	r := newRig(t)
	secretish := "zq7-unmistakable-marker-passphrase"
	r.run(t, secretish+"\n"+secretish+"\n", "init")
	next := "yw3-another-unmistakable-marker-phrase"
	r.run(t, secretish+"\n"+next+"\n"+next+"\n", "passwd")
	r.run(t, secretish+"x\n", "passwd")
	for _, marker := range []string{"unmistakable-marker"} {
		if strings.Contains(r.out.String()+r.err.String(), marker) {
			t.Errorf("a typed passphrase appears in the output:\n%s%s", r.out.String(), r.err.String())
		}
	}
}

func TestEndOfInputMidwayIsAnErrorForEveryPrompt(t *testing.T) {
	r := newRig(t)
	if code := r.run(t, good+"\n", "init"); code == 0 { // the confirmation is missing
		t.Fatal("init without the confirmation must fail")
	}
	if r.vault().State() != vault.NotInitialized {
		t.Error("nothing created")
	}
	r2 := newRig(t)
	r2.run(t, good+"\n"+good+"\n", "init")
	if code := r2.run(t, "", "passwd"); code == 0 {
		t.Fatal("passwd with no input must fail")
	}
	if err := r2.vault().Unlock(good); err != nil {
		t.Errorf("unchanged: %v", err)
	}
}

func TestStatusDoesNotOpenTheVault(t *testing.T) {
	r := newRig(t)
	r.run(t, good+"\n"+good+"\n", "init")
	v := r.vault()
	env := Env{Config: r.cfg, ConfigPath: r.cfgPath, Vault: v, In: strings.NewReader(""), Out: &r.out, Err: &r.err}
	Run([]string{"status"}, env)
	if v.State() != vault.Locked {
		t.Errorf("status only reports: %v", v.State())
	}
	if !strings.Contains(r.out.String(), "locked") {
		t.Error(r.out.String())
	}
}

func TestInitWithOldFilesReportsAndDoesNotLeakSecrets(t *testing.T) {
	r := newRig(t)
	link, _ := totp.NewSecret()
	totp.SaveSecret(r.cfg.Security.LinkTOTP.SecretFile, link)
	os.Chmod(r.cfg.Security.LinkTOTP.SecretFile, 0o644)
	r.run(t, good+"\n"+good+"\n", "init")
	out := r.out.String() + r.err.String()
	if strings.Contains(out, totp.FormatSecret(link)) {
		t.Error("the secret must not be printed")
	}
	if !strings.Contains(out, "WARNING") || !strings.Contains(out, "exposed") {
		t.Errorf("an exposed legacy secret must be called out:\n%s", out)
	}
}

// When the input has run out, the person must be told that, not that their (nonexistent) passphrase is too weak.
func TestRunningOutOfInputSaysSoInsteadOfBlamingThePassphrase(t *testing.T) {
	r := newRig(t)
	if code := r.run(t, "", "init"); code == 0 {
		t.Fatal("must fail")
	}
	if !strings.Contains(r.err.String(), "no more input") {
		t.Errorf("the real cause must be named: %q", r.err.String())
	}
	if strings.Contains(r.err.String(), "too weak") {
		t.Errorf("an absent passphrase is not a weak one: %q", r.err.String())
	}
	if n := strings.Count(r.out.String(), "New vault passphrase"); n != 1 {
		t.Errorf("it must stop at the first prompt that cannot be answered, not retry: asked %d times", n)
	}
}

// An existing vault can still be handed what an earlier version left in files (a leftover, or an old process that
// wrote after init).
func TestMigrateMovesLeftoversIntoAnExistingVault(t *testing.T) {
	r := newRig(t)
	r.run(t, good+"\n"+good+"\n", "init")
	link, _ := totp.NewSecret()
	if err := totp.SaveSecret(r.cfg.Security.LinkTOTP.SecretFile, link); err != nil {
		t.Fatal(err)
	}
	if code := r.run(t, good+"\n", "migrate"); code != 0 {
		t.Fatalf("exit %d: %s", code, r.err.String())
	}
	v := r.vault()
	if err := v.Unlock(good); err != nil {
		t.Fatal(err)
	}
	if raw, err := v.Get(config.LinkSecretName); err != nil || string(raw) != totp.FormatSecret(link) {
		t.Fatalf("the leftover must be in the vault: %v", err)
	}
	if _, err := os.Stat(r.cfg.Security.LinkTOTP.SecretFile); err == nil {
		t.Error("and the file must be gone")
	}
	if !strings.Contains(r.out.String(), "1 TOTP secret") {
		t.Errorf("%s", r.out.String())
	}
	if r.vault().State() != vault.Locked {
		t.Error("the vault is shut when the command ends")
	}
}

func TestMigrateNeedsTheRightPassphraseAndAVault(t *testing.T) {
	r := newRig(t)
	if code := r.run(t, good+"\n", "migrate"); code == 0 {
		t.Fatal("there is no vault to move things into")
	}
	if !strings.Contains(r.err.String(), "vault init") {
		t.Errorf("%q", r.err.String())
	}
	r.run(t, good+"\n"+good+"\n", "init")
	link, _ := totp.NewSecret()
	totp.SaveSecret(r.cfg.Security.LinkTOTP.SecretFile, link)
	if code := r.run(t, "not the passphrase at all\n", "migrate"); code == 0 {
		t.Fatal("a wrong passphrase must fail")
	}
	if _, err := os.Stat(r.cfg.Security.LinkTOTP.SecretFile); err != nil {
		t.Error("a refused migration must not touch the files")
	}
}

func TestMigrateWithNothingToDoSaysSo(t *testing.T) {
	r := newRig(t)
	r.run(t, good+"\n"+good+"\n", "init")
	if code := r.run(t, good+"\n", "migrate"); code != 0 {
		t.Fatalf("%s", r.err.String())
	}
	if !strings.Contains(r.out.String(), "nothing") {
		t.Errorf("a person who runs it twice should be told there is nothing left: %q", r.out.String())
	}
}

// plantEverything leaves one of each kind of file an earlier version made.
func plantEverything(t *testing.T, r *rig) (link, seal []byte) {
	t.Helper()
	link, _ = totp.NewSecret()
	seal, _ = totp.NewSecret()
	if err := totp.SaveSecret(r.cfg.Security.LinkTOTP.SecretFile, link); err != nil {
		t.Fatal(err)
	}
	if err := totp.SaveSecret(r.cfg.Security.SealTOTP.SecretFile, seal); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(r.cfg.Keys.Dir, 0o700)
	os.WriteFile(filepath.Join(r.cfg.Keys.Dir, "abcd1234.asc"), []byte("OLD KEY"), 0o600)
	os.MkdirAll(r.cfg.Sessions.Dir, 0o700)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	blk, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(blk)
	plain, _ := json.Marshal([]map[string]any{{"site": "gitlab", "base": "https://g.example", "tokens": map[string]string{"t": "OLD"}}})
	nonce := make([]byte, g.NonceSize())
	os.WriteFile(filepath.Join(r.cfg.Sessions.Dir, "sessions.key"), key, 0o600)
	os.WriteFile(filepath.Join(r.cfg.Sessions.Dir, "sessions.enc"), append(nonce, g.Seal(nil, nonce, plain, nil)...), 0o600)
	return link, seal
}

func assertEverythingMoved(t *testing.T, r *rig, link, seal []byte) {
	t.Helper()
	v := r.vault()
	if err := v.Unlock(good); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][]byte{config.LinkSecretName: link, config.SealSecretName: seal} {
		if raw, err := v.Get(name); err != nil || string(raw) != totp.FormatSecret(want) {
			t.Errorf("%s did not arrive intact: %v", name, err)
		}
	}
	if raw, err := v.Get("session/https://g.example"); err != nil || !strings.Contains(string(raw), "OLD") {
		t.Errorf("the stored session did not arrive: %v", err)
	}
	for _, p := range []string{r.cfg.Security.LinkTOTP.SecretFile, r.cfg.Security.SealTOTP.SecretFile,
		filepath.Join(r.cfg.Sessions.Dir, "sessions.enc"), filepath.Join(r.cfg.Sessions.Dir, "sessions.key"),
		filepath.Join(r.cfg.Keys.Dir, "abcd1234.asc")} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s was not removed", p)
		}
	}
}

func TestInitMovesEveryKindOfOldFile(t *testing.T) {
	r := newRig(t)
	link, seal := plantEverything(t, r)
	if code := r.run(t, good+"\n"+good+"\n", "init"); code != 0 {
		t.Fatal(r.err.String())
	}
	assertEverythingMoved(t, r, link, seal)
}

func TestMigrateMovesEveryKindOfOldFile(t *testing.T) {
	r := newRig(t)
	r.run(t, good+"\n"+good+"\n", "init")
	link, seal := plantEverything(t, r)
	if code := r.run(t, good+"\n", "migrate"); code != 0 {
		t.Fatal(r.err.String())
	}
	assertEverythingMoved(t, r, link, seal)
}

func TestMigrateOnAVaultThatWasNeverMadeAsksForNothing(t *testing.T) {
	r := newRig(t)
	r.run(t, good+"\n", "migrate")
	if strings.Contains(r.out.String(), "passphrase") {
		t.Errorf("there is nothing to open, so there is nothing to ask for:\n%s", r.out.String())
	}
	if r.vault().State() != vault.NotInitialized {
		t.Error("migrate must not make a vault")
	}
}

func TestMigrateWithAWrongPassphraseTouchesNothingAndAsksForNoOther(t *testing.T) {
	r := newRig(t)
	r.run(t, good+"\n"+good+"\n", "init")
	plantEverything(t, r)
	if code := r.run(t, "definitely not the passphrase\n"+good+"\n", "migrate"); code == 0 {
		t.Fatal("must fail")
	}
	if strings.Count(r.out.String(), "passphrase") != 1 {
		t.Errorf("one wrong attempt ends the command; it must not offer another try:\n%s", r.out.String())
	}
	for _, p := range []string{r.cfg.Security.LinkTOTP.SecretFile, filepath.Join(r.cfg.Sessions.Dir, "sessions.enc"), filepath.Join(r.cfg.Keys.Dir, "abcd1234.asc")} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s must be untouched: %v", p, err)
		}
	}
}

func TestMigrateShutsTheVaultEvenWhenItFindsProblems(t *testing.T) {
	r := newRig(t)
	r.run(t, good+"\n"+good+"\n", "init")
	os.MkdirAll(filepath.Dir(r.cfg.Security.LinkTOTP.SecretFile), 0o700)
	os.WriteFile(r.cfg.Security.LinkTOTP.SecretFile, []byte("not a secret at all !!!"), 0o600)
	v := r.vault()
	env := Env{Config: r.cfg, ConfigPath: r.cfgPath, Vault: v, In: strings.NewReader(good + "\n"), Out: &r.out, Err: &r.err}
	Run([]string{"migrate"}, env)
	if v.State() != vault.Locked {
		t.Errorf("the key must not stay in memory: %v", v.State())
	}
}

func TestMigrateNamesAWrongPassphraseAsSuch(t *testing.T) {
	r := newRig(t)
	r.run(t, good+"\n"+good+"\n", "init")
	if code := r.run(t, "definitely not the passphrase\n", "migrate"); code == 0 {
		t.Fatal("must fail")
	}
	if !strings.Contains(r.err.String(), "wrong") {
		t.Errorf("the person must be told the passphrase was wrong, not that something deeper failed: %q", r.err.String())
	}
	if strings.Contains(r.err.String(), "locked") {
		t.Errorf("a wrong passphrase is not 'the vault is locked': %q", r.err.String())
	}
}
