package configcli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/totp"
	"github.com/LeafAI/securl/internal/vault"
)

var fixedNow = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

const vaultPass = "correct horse battery staple"

// vaultNextTo opens (creating it on first use) the vault that sits next to a config file.
func vaultNextTo(t *testing.T, cfgPath string) *vault.Vault {
	t.Helper()
	v := vault.NewWithCost(filepath.Join(filepath.Dir(cfgPath), "vault"), 1, 8, 1)
	switch v.State() {
	case vault.NotInitialized:
		if err := v.Init(vaultPass); err != nil {
			t.Fatal(err)
		}
	case vault.Locked:
		if err := v.Unlock(vaultPass); err != nil {
			t.Fatal(err)
		}
	}
	return v
}

// runAt is run with a fixed clock, so codes are predictable, and with the vault open.
func runAt(t *testing.T, path, answers string, args ...string) result {
	t.Helper()
	if path == "" {
		path = filepath.Join(t.TempDir(), "login", "config.yaml")
	}
	var out, errb bytes.Buffer
	env := Env{Path: path, In: strings.NewReader(answers), Out: &out, Err: &errb, Now: func() time.Time { return fixedNow },
		Vault: vaultNextTo(t, path)}
	code := Run(args, env)
	return result{code, out.String(), errb.String(), path}
}

func secretOf(t *testing.T, cfgPath, name string) []byte {
	t.Helper()
	raw, err := vaultNextTo(t, cfgPath).Get("totp/" + name)
	if err != nil {
		t.Fatalf("secret %s: %v", name, err)
	}
	b, err := totp.ParseSecret(string(raw))
	if err != nil {
		t.Fatalf("secret %s: %v", name, err)
	}
	return b
}

func hasSecret(t *testing.T, cfgPath, name string) bool {
	t.Helper()
	_, err := vaultNextTo(t, cfgPath).Get("totp/" + name)
	return err == nil
}

// init creates the secrets, turns the factors on, and shows each secret so it can be registered in an authenticator.
func TestTOTPInitCreatesBothFactors(t *testing.T) {
	r := runAt(t, "", "", "totp", "init")
	if r.code != 0 {
		t.Fatalf("exit %d: %s%s", r.code, r.out, r.err)
	}
	link, seal := secretOf(t, r.path, "link"), secretOf(t, r.path, "seal")
	if string(link) == string(seal) {
		t.Fatal("the two factors share a secret")
	}
	c := load(t, r.path)
	if !c.Security.LinkTOTP.Enabled || !c.Security.SealTOTP.Enabled {
		t.Fatalf("the factors must be switched on: %+v", c.Security)
	}
	// each secret is shown (text form, and the otpauth URI with its period) so it can be registered
	for _, want := range []string{totp.FormatSecret(link), totp.FormatSecret(seal), "otpauth://totp/", "period=600", "period=30"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("the output lacks %q:\n%s", want, r.out)
		}
	}
	// no secret file is made: the secrets exist only inside the vault
	for _, f := range []string{"link", "seal"} {
		if fileExists(filepath.Join(filepath.Dir(r.path), "totp", f+".secret")) {
			t.Errorf("%s secret was also written to a file", f)
		}
	}
	filepath.WalkDir(filepath.Dir(r.path), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, _ := os.ReadFile(p)
		for _, sec := range [][]byte{link, seal} {
			if bytes.Contains(raw, []byte(totp.FormatSecret(sec))) {
				t.Errorf("%s holds a TOTP secret in the clear", p)
			}
		}
		return nil
	})
}

// Never replace a secret that has been registered: running init again must not lock anybody out.
func TestTOTPInitDoesNotReplaceExistingSecrets(t *testing.T) {
	r := runAt(t, "", "", "totp", "init")
	before := secretOf(t, r.path, "link")
	r2 := runAt(t, r.path, "", "totp", "init")
	if r2.code == 0 {
		t.Fatalf("a second init succeeded:\n%s", r2.out)
	}
	if !strings.Contains(r2.err, "already") {
		t.Errorf("the refusal must say why: %q", r2.err)
	}
	if string(secretOf(t, r.path, "link")) != string(before) {
		t.Fatal("an existing secret was replaced")
	}
}

// `code` prints the code of the moment, for people whose authenticator cannot do the long period.
func TestTOTPCodePrintsTheCurrentCodes(t *testing.T) {
	r := runAt(t, "", "", "totp", "init")
	link, seal := secretOf(t, r.path, "link"), secretOf(t, r.path, "seal")
	out := runAt(t, r.path, "", "totp", "code")
	if out.code != 0 {
		t.Fatalf("exit %d: %s", out.code, out.err)
	}
	wantLink := totp.Code(link, fixedNow, 10*time.Minute, 8)
	wantSeal := totp.Code(seal, fixedNow, 30*time.Second, 8)
	for _, want := range []string{wantLink, wantSeal} {
		if !strings.Contains(out.out, want) {
			t.Errorf("the output lacks the code %s:\n%s", want, out.out)
		}
	}
	// and says how long each is valid, so nobody types a code that is about to change
	if !strings.Contains(out.out, "valid for") {
		t.Errorf("the output should say how long each code is valid:\n%s", out.out)
	}
	// one factor at a time
	one := runAt(t, r.path, "", "totp", "code", "link")
	if !strings.Contains(one.out, wantLink) || strings.Contains(one.out, wantSeal) {
		t.Errorf("`code link` should print only the unlock code:\n%s", one.out)
	}
}

func TestTOTPStatusShowsSettingsButNeverTheSecretOrACode(t *testing.T) {
	r := runAt(t, "", "", "totp", "init")
	link := secretOf(t, r.path, "link")
	st := runAt(t, r.path, "", "totp", "status")
	if st.code != 0 {
		t.Fatalf("%s", st.err)
	}
	for _, leak := range []string{totp.FormatSecret(link), totp.Code(link, fixedNow, 10*time.Minute, 8)} {
		if strings.Contains(st.out, leak) {
			t.Errorf("status leaks %q:\n%s", leak, st.out)
		}
	}
	for _, want := range []string{"unlock", "sealing", "10m0s", "30s", "8 digits"} {
		if !strings.Contains(st.out, want) {
			t.Errorf("status lacks %q:\n%s", want, st.out)
		}
	}
}

func TestTOTPStatusWhenNothingIsConfigured(t *testing.T) {
	st := runAt(t, "", "", "totp", "status")
	if st.code != 0 || !strings.Contains(st.out, "off") {
		t.Fatalf("%d %q %q", st.code, st.out, st.err)
	}
}

// off switches a factor off but keeps its secret: the person's authenticator entry stays valid for turning it back on.
func TestTOTPOffKeepsTheSecret(t *testing.T) {
	r := runAt(t, "", "", "totp", "init")
	before := secretOf(t, r.path, "link")
	if off := runAt(t, r.path, "", "totp", "off", "link"); off.code != 0 {
		t.Fatalf("%s", off.err)
	}
	c := load(t, r.path)
	if c.Security.LinkTOTP.Enabled || !c.Security.SealTOTP.Enabled {
		t.Fatalf("only the unlock factor should be off: %+v", c.Security)
	}
	if string(secretOf(t, r.path, "link")) != string(before) {
		t.Fatal("switching a factor off removed its secret")
	}
	if on := runAt(t, r.path, "", "totp", "on", "link"); on.code != 0 || !load(t, r.path).Security.LinkTOTP.Enabled {
		t.Fatalf("on: %d %s", on.code, on.err)
	}
}

// Each factor can be set up on its own.
func TestTOTPInitOneFactor(t *testing.T) {
	r := runAt(t, "", "", "totp", "init", "seal")
	c := load(t, r.path)
	if c.Security.LinkTOTP.Enabled || !c.Security.SealTOTP.Enabled {
		t.Fatalf("only the sealing factor should be on: %+v", c.Security)
	}
	if hasSecret(t, r.path, "link") {
		t.Error("a secret was created for the factor that was not asked for")
	}
}

func TestTOTPUnknownFactorOrCommand(t *testing.T) {
	for _, args := range [][]string{{"totp"}, {"totp", "bogus"}, {"totp", "init", "nope"}, {"totp", "code", "nope"}, {"totp", "off"}} {
		if r := runAt(t, "", "", args...); r.code == 0 {
			t.Errorf("%v succeeded", args)
		}
	}
}

// `on` without a secret must refuse rather than switch on a factor that cannot work (the server would not start).
func TestTOTPOnWithoutASecretIsRefused(t *testing.T) {
	r := runAt(t, "", "", "totp", "on", "link")
	if r.code == 0 {
		t.Fatalf("a factor was switched on without a secret:\n%s", r.out)
	}
	if !strings.Contains(r.err, "init") {
		t.Errorf("the refusal should point at `totp init`: %q", r.err)
	}
}

// The command checks every secret before it creates any, so a refused init leaves nothing behind. This is only visible
// when the secret that exists comes LATER in the order than one that does not: then an implementation that checks as it
// goes would already have created the earlier one when it hits the later. (The unlock factor is handled first, so the
// sealing secret is the one that exists here.)
func TestTOTPInitIsAllOrNothing(t *testing.T) {
	r := runAt(t, "", "", "totp", "init", "seal") // only the sealing secret exists now
	if hasSecret(t, r.path, "link") {
		t.Fatal("test setup: the unlock secret should not exist yet")
	}
	both := runAt(t, r.path, "", "totp", "init") // asks for both; the sealing one exists
	if both.code == 0 {
		t.Fatal("init succeeded although one of the secrets already exists")
	}
	if hasSecret(t, r.path, "link") {
		t.Fatal("init made the unlock secret before noticing that the sealing secret exists: a half-done state")
	}
	if c := load(t, r.path); c.Security.LinkTOTP.Enabled {
		t.Fatal("the unlock factor was switched on by a refused init")
	}
}

// The secrets of the two factors are independent random values: made one after the other, never the same.
func TestTOTPInitMakesIndependentSecrets(t *testing.T) {
	for i := 0; i < 5; i++ {
		r := runAt(t, "", "", "totp", "init")
		if string(secretOf(t, r.path, "link")) == string(secretOf(t, r.path, "seal")) {
			t.Fatal("the two factors got the same secret")
		}
	}
}

// The secrets are in the vault, so the commands need it open. A vault that was never made is said so, with the command
// that makes it. One that is locked is opened by asking for the passphrase; with no way to answer, that is what the
// message says. Either way nothing is changed.
func TestTOTPCommandsNeedAnOpenVault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "login", "config.yaml")
	for _, state := range []string{"not initialized", "locked"} {
		v := vault.NewWithCost(filepath.Join(filepath.Dir(path), "vault"), 1, 8, 1)
		if state == "locked" {
			if err := v.Init(vaultPass); err != nil {
				t.Fatal(err)
			}
			v.Lock()
		}
		for _, args := range [][]string{{"totp", "init"}, {"totp", "code"}, {"totp", "status"}, {"totp", "on", "link"}} {
			var out, errb bytes.Buffer
			env := Env{Path: path, In: strings.NewReader(""), Out: &out, Err: &errb, Now: func() time.Time { return fixedNow }, Vault: v}
			if code := Run(args, env); code == 0 && args[1] != "status" {
				t.Errorf("%s %v: succeeded without an open vault", state, args)
			}
			want := map[string]string{"not initialized": "vault init", "locked": "passphrase"}[state]
			if args[1] != "status" && !strings.Contains(errb.String(), want) {
				t.Errorf("%s %v: the message must say how to fix it (%q): %q", state, args, want, errb.String())
			}
		}
		if _, err := os.Stat(path); err == nil {
			t.Errorf("%s: a refused command must not have written the config", state)
		}
	}
}

func TestTOTPStatusWorksWithALockedVaultAndNeverShowsSecrets(t *testing.T) {
	r := runAt(t, "", "", "totp", "init")
	link := secretOf(t, r.path, "link")
	v := vault.NewWithCost(filepath.Join(filepath.Dir(r.path), "vault"), 1, 8, 1) // a fresh handle: locked
	var out, errb bytes.Buffer
	env := Env{Path: r.path, In: strings.NewReader(""), Out: &out, Err: &errb, Now: func() time.Time { return fixedNow }, Vault: v}
	if code := Run([]string{"totp", "status"}, env); code != 0 {
		t.Fatalf("status must work while locked, it only reports: %d %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "locked") {
		t.Errorf("status should say it cannot check the secrets because the vault is locked:\n%s", out.String())
	}
	if strings.Contains(out.String(), totp.FormatSecret(link)) {
		t.Error("status leaks the secret")
	}
}

func TestTOTPInitRefusesWhenTheSecretExistsInTheVaultEvenIfTheConfigIsFresh(t *testing.T) {
	r := runAt(t, "", "", "totp", "init")
	before := secretOf(t, r.path, "link")
	os.Remove(r.path) // the config was lost; the vault was not
	again := runAt(t, r.path, "", "totp", "init")
	if again.code == 0 {
		t.Fatal("init must not replace a secret that is in the vault, whatever the config says")
	}
	if string(secretOf(t, r.path, "link")) != string(before) {
		t.Fatal("the secret in the vault was replaced")
	}
}

// A command line process cannot borrow the key of a running server, so when the vault is shut it asks for the
// passphrase itself, opens its own copy, does its work and shuts it again.

func lockedVaultRun(t *testing.T, pass string, args ...string) (result, *vault.Vault) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "login", "config.yaml")
	v := vault.NewWithCost(filepath.Join(filepath.Dir(path), "vault"), 1, 8, 1)
	if err := v.Init(vaultPass); err != nil {
		t.Fatal(err)
	}
	v.Lock()
	var out, errb bytes.Buffer
	env := Env{Path: path, In: strings.NewReader(pass), Out: &out, Err: &errb, Now: func() time.Time { return fixedNow }, Vault: v}
	code := Run(args, env)
	return result{code, out.String(), errb.String(), path}, v
}

func TestTOTPInitAsksForThePassphraseWhenTheVaultIsLocked(t *testing.T) {
	r, v := lockedVaultRun(t, vaultPass+"\n", "totp", "init")
	if r.code != 0 {
		t.Fatalf("exit %d: %s%s", r.code, r.out, r.err)
	}
	if v.State() != vault.Locked {
		t.Error("the command must shut the vault again when it is done")
	}
	if strings.Contains(r.out+r.err, vaultPass) {
		t.Error("the passphrase must not be printed")
	}
	if err := v.Unlock(vaultPass); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get("totp/link"); err != nil {
		t.Errorf("the secret was made in the vault: %v", err)
	}
}

func TestAWrongPassphraseChangesNothing(t *testing.T) {
	r, v := lockedVaultRun(t, "this is not the passphrase\n", "totp", "init")
	if r.code == 0 {
		t.Fatal("a wrong passphrase must fail")
	}
	if !strings.Contains(r.err, "wrong") {
		t.Errorf("%q", r.err)
	}
	if v.State() != vault.Locked {
		t.Error("still locked")
	}
	if _, err := os.Stat(r.path); err == nil {
		t.Error("a refused command must not write the config")
	}
}

func TestTheVaultIsShutAgainEvenWhenTheCommandFails(t *testing.T) {
	// init twice: the second finds the secrets and refuses, after the vault was opened for it
	r, v := lockedVaultRun(t, vaultPass+"\n", "totp", "init")
	if r.code != 0 {
		t.Fatal(r.err)
	}
	var out, errb bytes.Buffer
	env := Env{Path: r.path, In: strings.NewReader(vaultPass + "\n"), Out: &out, Err: &errb, Now: func() time.Time { return fixedNow }, Vault: v}
	if code := Run([]string{"totp", "init"}, env); code == 0 {
		t.Fatal("the second init must refuse")
	}
	if v.State() != vault.Locked {
		t.Error("a failed command must still shut the vault it opened")
	}
}

func TestStatusNeverAsksForAPassphrase(t *testing.T) {
	r, v := lockedVaultRun(t, "", "totp", "status")
	if r.code != 0 {
		t.Fatalf("%s", r.err)
	}
	if strings.Contains(r.out, "passphrase") {
		t.Errorf("status only reports and must not prompt:\n%s", r.out)
	}
	if v.State() != vault.Locked {
		t.Error("and must not open the vault")
	}
}

func TestAnUninitializedVaultIsNotPromptedForAPassphrase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "login", "config.yaml")
	v := vault.NewWithCost(filepath.Join(filepath.Dir(path), "vault"), 1, 8, 1)
	var out, errb bytes.Buffer
	env := Env{Path: path, In: strings.NewReader(vaultPass + "\n"), Out: &out, Err: &errb, Vault: v}
	if code := Run([]string{"totp", "init"}, env); code == 0 {
		t.Fatal("there is no vault to open")
	}
	if !strings.Contains(errb.String(), "vault init") {
		t.Errorf("it should say how to make one: %q", errb.String())
	}
	if strings.Contains(out.String(), "passphrase") {
		t.Errorf("it must not ask for a passphrase of a vault that does not exist:\n%s", out.String())
	}
}

// Two prompts in one command read from one input. A second reader over the same stream would lose what the first one
// had already buffered.
func TestTwoPassphrasePromptsShareOneInput(t *testing.T) {
	_, v := lockedVaultRun(t, vaultPass+"\n", "totp", "status") // make the vault
	var out, errb bytes.Buffer
	env := Env{In: strings.NewReader(vaultPass + "\n" + vaultPass + "\n"), Out: &out, Err: &errb, Vault: v}
	envp := &env
	a, err1 := askPassphraseOn(envp)
	b, err2 := askPassphraseOn(envp)
	if err1 != nil || err2 != nil || a != vaultPass || b != vaultPass {
		t.Fatalf("both lines must be read: %q %v / %q %v", a, err1, b, err2)
	}
}

func TestPassphraseKeepsItsSpacesWhenTypedForACommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "login", "config.yaml")
	pass := "  spaces matter in a passphrase  "
	v := vault.NewWithCost(filepath.Join(filepath.Dir(path), "vault"), 1, 8, 1)
	if err := v.Init(pass); err != nil {
		t.Fatal(err)
	}
	v.Lock()
	var out, errb bytes.Buffer
	env := Env{Path: path, In: strings.NewReader(pass + "\n"), Out: &out, Err: &errb, Now: func() time.Time { return fixedNow }, Vault: v}
	if code := Run([]string{"totp", "init"}, env); code != 0 {
		t.Fatalf("a passphrase must be used exactly as typed: %s", errb.String())
	}
}

func TestNoPassphraseToReadIsReportedAsThatNotAsAWrongOne(t *testing.T) {
	for _, args := range [][]string{{"totp", "init"}, {"totp", "code"}, {"totp", "on", "link"}} {
		r, _ := lockedVaultRun(t, "", args...)
		if r.code == 0 {
			t.Errorf("%v: succeeded without a passphrase", args)
		}
		if !strings.Contains(r.err, "no passphrase could be read") {
			t.Errorf("%v: the real cause must be named: %q", args, r.err)
		}
		if strings.Contains(r.err, "wrong") {
			t.Errorf("%v: nobody typed a wrong passphrase: %q", args, r.err)
		}
	}
}

// Every command that opens the vault shuts it again, whether it succeeds or not.
func TestEveryTOTPCommandShutsTheVaultItOpened(t *testing.T) {
	for _, args := range [][]string{{"totp", "init"}, {"totp", "code"}, {"totp", "on", "link"}, {"totp", "init", "seal"}} {
		path := filepath.Join(t.TempDir(), "login", "config.yaml")
		v := vault.NewWithCost(filepath.Join(filepath.Dir(path), "vault"), 1, 8, 1)
		if err := v.Init(vaultPass); err != nil {
			t.Fatal(err)
		}
		v.Lock()
		var out, errb bytes.Buffer
		env := Env{Path: path, In: strings.NewReader(vaultPass + "\n"), Out: &out, Err: &errb, Now: func() time.Time { return fixedNow }, Vault: v}
		Run(args, env) // some succeed, some fail (code and on have no secret yet): both must shut it
		if v.State() != vault.Locked {
			t.Errorf("%v left the vault open", args)
		}
	}
}
