package dbsite

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/dbexec"
	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/site/sitetest"
)

var target = config.Database{Name: "gm-dev-pg", Driver: config.DriverPostgres, Host: "pg.dev.corp.example", Port: 5432, Environment: "dev", Mode: config.ModeReadOnly}

type fakeOpener struct {
	gotCreds dbexec.Credentials
	gotDB    string
	err      error
	opened   int
}

func (f *fakeOpener) open(_ context.Context, _ config.Database, c dbexec.Credentials, db string) error {
	f.opened++
	f.gotCreds, f.gotDB = c, db
	return f.err
}

func lookup(name string) (config.Database, bool) {
	if name == target.Name {
		return target, true
	}
	return config.Database{}, false
}

func newDriver(f *fakeOpener) *Driver { return New(lookup, f.open) }

func asker(user, pass string) *sitetest.Asker {
	return &sitetest.Asker{Answers: map[string]site.Credentials{"login": {"username": user, "password": pass}}}
}

func TestTheKeyOfATargetCannotBeAnHTTPSite(t *testing.T) {
	k := Key("gm-dev-pg")
	u, err := url.Parse(k)
	if err != nil || u.Scheme != Scheme || u.Host != "gm-dev-pg" {
		t.Fatalf("%q: %v", k, err)
	}
	if strings.HasPrefix(k, "http") {
		t.Errorf("a target must not look like a web site: %s", k)
	}
	if got := site.Key(u); got != k {
		t.Errorf("the session cache keys on site.Key: %q vs %q", got, k)
	}
}

func TestLoginAsksForUsernameAndPasswordAndChecksThemByConnecting(t *testing.T) {
	f := &fakeOpener{}
	d := newDriver(f)
	a := asker("alice", "s3cret-pass")
	s, err := d.Login(context.Background(), BaseURL("gm-dev-pg"), a, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Asked) != 1 || a.Asked[0] != "login" {
		t.Errorf("asked %v", a.Asked)
	}
	if f.opened != 1 || f.gotCreds.Username != "alice" || f.gotCreds.Password != "s3cret-pass" {
		t.Errorf("the login must be tried against the database: %+v", f)
	}
	if s.Tokens[TokenUser] != "alice" || s.Tokens[TokenPassword] != "s3cret-pass" {
		t.Errorf("the credentials are kept in the session, which the vault holds: %v", s.Tokens)
	}
	if len(s.Cookies) != 0 || len(s.Headers) != 0 {
		t.Error("a database session carries no cookies or headers")
	}
}

func TestLoginTellsApartWrongPasswordAndUnreachable(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want error
	}{
		"bad credentials": {dbexec.ErrBadCredentials, site.ErrBadCredentials},
		"unreachable":     {dbexec.ErrUnreachable, site.ErrUnreachable},
		"local address":   {dbexec.ErrLocalAddress, site.ErrLoginRejected},
		"other":           {errors.New("boom"), site.ErrLoginRejected},
	} {
		f := &fakeOpener{err: tc.err}
		_, err := newDriver(f).Login(context.Background(), BaseURL("gm-dev-pg"), asker("a", "b"), nil)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: want %v, got %v", name, tc.want, err)
		}
	}
}

func TestLoginErrorNeverCarriesThePassword(t *testing.T) {
	f := &fakeOpener{err: errors.New("could not connect as alice with password s3cret-pass")}
	_, err := newDriver(f).Login(context.Background(), BaseURL("gm-dev-pg"), asker("alice", "s3cret-pass"), nil)
	if err == nil || strings.Contains(err.Error(), "s3cret-pass") {
		t.Errorf("%v", err)
	}
}

func TestLoginRefusesAnEmptyUsername(t *testing.T) {
	f := &fakeOpener{}
	_, err := newDriver(f).Login(context.Background(), BaseURL("gm-dev-pg"), asker("  ", "x"), nil)
	if !errors.Is(err, site.ErrBadCredentials) || f.opened != 0 {
		t.Errorf("%v, opened %d", err, f.opened)
	}
}

func TestLoginFieldsAreTheStandardPair(t *testing.T) {
	if len(site.LoginFields) != 2 {
		t.Skip()
	}
	a := &captureFields{}
	_, _ = newDriver(&fakeOpener{}).Login(context.Background(), BaseURL("gm-dev-pg"), a, nil)
	if len(a.fields) != 2 || a.fields[0].Name != "username" || a.fields[1].Name != "password" || !a.fields[1].Secret {
		t.Errorf("%+v", a.fields)
	}
}

type captureFields struct{ fields []site.Field }

func (c *captureFields) Ask(_ context.Context, _ string, f []site.Field) (site.Credentials, error) {
	c.fields = f
	return site.Credentials{"username": "u", "password": "p"}, nil
}

func TestProbeChecksTheStoredCredentialsStillWork(t *testing.T) {
	f := &fakeOpener{}
	d := newDriver(f)
	s := &site.Session{Tokens: map[string]string{TokenUser: "alice", TokenPassword: "pw"}}
	if err := d.Probe(context.Background(), BaseURL("gm-dev-pg"), s, nil); err != nil {
		t.Fatal(err)
	}
	if f.opened != 1 || f.gotCreds.Username != "alice" || f.gotCreds.Password != "pw" {
		t.Errorf("%+v", f)
	}
	f.err = dbexec.ErrBadCredentials
	if err := d.Probe(context.Background(), BaseURL("gm-dev-pg"), s, nil); err == nil {
		t.Error("a password the database no longer accepts must end the session")
	}
	if err := d.Probe(context.Background(), BaseURL("gm-dev-pg"), &site.Session{}, nil); err == nil {
		t.Error("a session without credentials is not valid")
	}
}

func TestADriverIsNeverMatchedByAURLAndNeedsALogin(t *testing.T) {
	d := newDriver(&fakeOpener{})
	if !d.NeedsLogin() {
		t.Error("a database needs credentials")
	}
	for _, raw := range []string{"https://pg.dev.corp.example", "http://gm-dev-pg", "db://gm-dev-pg", ""} {
		u, _ := url.Parse(raw)
		if d.Match(u) {
			t.Errorf("%q: the web tools must never pick a database driver from a URL", raw)
		}
	}
	if d.Name() != "gm-dev-pg" && d.Name() != "database" {
		t.Errorf("name %q", d.Name())
	}
}

func TestNewSessionIsNotHTTP(t *testing.T) {
	var _ site.Driver = newDriver(&fakeOpener{})
	_ = http.StatusOK
}

// The session cache finds a driver by the name a session was filed under, and then hands it the session's key; the driver
// finds its target from that key. A key that names no configured target (the target was removed from the configuration
// after the session was stored) must not open anything.
func TestAKeyThatNamesNoTargetIsRefused(t *testing.T) {
	f := &fakeOpener{}
	d := newDriver(f)
	s := &site.Session{Tokens: map[string]string{TokenUser: "a", TokenPassword: "b"}}
	if err := d.Probe(context.Background(), BaseURL("removed-target"), s, nil); !errors.Is(err, site.ErrLoginRejected) {
		t.Errorf("probe: %v", err)
	}
	if _, err := d.Login(context.Background(), BaseURL("removed-target"), asker("a", "b"), nil); !errors.Is(err, site.ErrLoginRejected) {
		t.Errorf("login: %v", err)
	}
	if f.opened != 0 {
		t.Error("nothing may be opened for a target that is not configured")
	}
}

func TestTheDriverOpensTheTargetTheKeyNames(t *testing.T) {
	other := config.Database{Name: "other", Driver: config.DriverMySQL, Host: "my.dev.corp.example", Port: 3306, Environment: "dev", Mode: config.ModeReadOnly, Databases: []string{"appdb"}}
	var gotTarget config.Database
	var gotDB string
	d := New(func(n string) (config.Database, bool) {
		if n == "other" {
			return other, true
		}
		return config.Database{}, false
	}, func(_ context.Context, t config.Database, _ dbexec.Credentials, db string) error {
		gotTarget, gotDB = t, db
		return nil
	})
	if _, err := d.Login(context.Background(), BaseURL("other"), asker("a", "b"), nil); err != nil {
		t.Fatal(err)
	}
	if gotTarget.Name != "other" || gotDB != "appdb" {
		t.Errorf("%+v %q", gotTarget, gotDB)
	}
}

// "The database could not be opened" told nobody what to fix. What went wrong is now said in the owner's terms, using only
// the package's own errors, so it can never carry what a driver echoed (a connection string, a user, a password).
func TestLoginSaysWhatWentWrongWithoutEchoingTheDriver(t *testing.T) {
	for name, tc := range map[string]struct {
		err        error
		wantIn     string
		wantNotIn  []string
		wantTarget error
	}{
		"database not allowed": {dbexec.ErrDatabaseNotAllowed, "databases", nil, site.ErrLoginRejected},
		"timeout":              {dbexec.ErrTimeout, "timed out", nil, site.ErrUnreachable},
		"unreachable detail": {fmt.Errorf("%w: tls: failed to verify certificate: x509: certificate is not trusted", dbexec.ErrUnreachable),
			"certificate", nil, site.ErrUnreachable},
	} {
		f := &fakeOpener{err: tc.err}
		_, err := newDriver(f).Login(context.Background(), BaseURL("gm-dev-pg"), asker("alice", "s3cret-pass"), nil)
		if !errors.Is(err, tc.wantTarget) {
			t.Errorf("%s: want %v, got %v", name, tc.wantTarget, err)
			continue
		}
		if !strings.Contains(strings.ToLower(err.Error()), tc.wantIn) {
			t.Errorf("%s: the message should say %q: %v", name, tc.wantIn, err)
		}
		if strings.Contains(err.Error(), "s3cret-pass") || strings.Contains(err.Error(), "alice") {
			t.Errorf("%s: the message carries the account: %v", name, err)
		}
	}
	// An error this package does not know is still kept out of the message.
	f := &fakeOpener{err: errors.New("dial tcp alice:s3cret-pass@10.0.0.1:3306: refused")}
	_, err := newDriver(f).Login(context.Background(), BaseURL("gm-dev-pg"), asker("alice", "s3cret-pass"), nil)
	if err == nil || strings.Contains(err.Error(), "s3cret-pass") || strings.Contains(err.Error(), "10.0.0.1") {
		t.Errorf("%v", err)
	}
}
