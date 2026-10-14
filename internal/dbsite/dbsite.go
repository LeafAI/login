// Package dbsite makes a configured database look like a site to the login machinery: a person types a username and a
// password on the usual page, the pair is checked by connecting once, and it is kept in the vault like any other session.
//
// A database is never a web site. Its key is db://<name>, a scheme that the HTTP tools refuse, and its driver is never
// matched from a URL, so request and session_open cannot reach one by accident or by an agent's choice; only the
// database tools, which take a configured name, can.
package dbsite

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/dbexec"
	"github.com/LeafAI/securl/internal/site"
)

// Scheme is the URL scheme of a database's session key.
const Scheme = "db"

// The names under which a session keeps the credentials.
const (
	TokenUser     = "db_user"
	TokenPassword = "db_password"
)

// BaseURL is the URL a database target is known by inside securl.
func BaseURL(name string) *url.URL { return &url.URL{Scheme: Scheme, Host: name} }

// Key is the session key of a target.
func Key(name string) string { return site.Key(BaseURL(name)) }

// Opener tries a login against the database (and closes the connection at once). It is a seam: the product connects for
// real, a test hands in a fake.
type Opener func(ctx context.Context, t config.Database, c dbexec.Credentials, database string) error

// Lookup finds a configured target by name.
type Lookup func(name string) (config.Database, bool)

// Driver is the login driver of every database target. The session cache finds a driver by the name a session is filed
// under, so there is one, and it finds the target from the session's key (db://<name>).
type Driver struct {
	lookup Lookup
	open   Opener
}

// New returns the driver.
func New(lookup Lookup, open Opener) *Driver { return &Driver{lookup: lookup, open: open} }

// Name is what the session is filed under.
func (d *Driver) Name() string { return "database" }

// Match never matches: a database is chosen by name, never recognised from a URL.
func (*Driver) Match(*url.URL) bool { return false }

// NeedsLogin is true: the account is the whole point.
func (*Driver) NeedsLogin() bool { return true }

// Login asks for the account and checks it by connecting.
func (d *Driver) Login(ctx context.Context, base *url.URL, ask site.Asker, _ *http.Client) (*site.Session, error) {
	target, err := d.target(base)
	if err != nil {
		return nil, err
	}
	creds, err := ask.Ask(ctx, "login", site.LoginFields)
	if err != nil {
		return nil, err
	}
	user, pass := strings.TrimSpace(creds["username"]), creds["password"]
	creds["password"] = ""
	if user == "" {
		return nil, fmt.Errorf("%w: the username is empty", site.ErrBadCredentials)
	}
	if err := d.try(ctx, target, user, pass); err != nil {
		return nil, err
	}
	return &site.Session{Tokens: map[string]string{TokenUser: user, TokenPassword: pass}}, nil
}

// Probe checks that the kept credentials are still accepted. A password that was changed ends the session, as a cookie
// the server no longer knows would.
func (d *Driver) Probe(ctx context.Context, base *url.URL, s *site.Session, _ *http.Client) error {
	target, err := d.target(base)
	if err != nil {
		return err
	}
	user, pass := s.Tokens[TokenUser], s.Tokens[TokenPassword]
	if user == "" || pass == "" {
		return fmt.Errorf("%w: the session holds no credentials", site.ErrBadCredentials)
	}
	return d.try(ctx, target, user, pass)
}

// target finds the configured target a key names.
func (d *Driver) target(base *url.URL) (config.Database, error) {
	if base == nil || base.Scheme != Scheme {
		return config.Database{}, fmt.Errorf("%w: not a database key", site.ErrLoginRejected)
	}
	t, ok := d.lookup(base.Host)
	if !ok {
		return config.Database{}, fmt.Errorf("%w: no database %q is configured", site.ErrLoginRejected, base.Host)
	}
	return t, nil
}

// unreachableHint adds the reason a connection failed when it is one the owner can act on. Only two kinds of reason are
// recognised, by what the package's own error says about them; anything else gets nothing, so what a driver echoed can
// never reach the message.
func unreachableHint(err error) string {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "certificate") || strings.Contains(msg, "x509"):
		return " (its TLS certificate is not trusted on this machine: install the CA, or the owner sets tls: skip-verify for this target)"
	case strings.Contains(msg, "refused"):
		return " (the connection was refused: check the host, the port and the network)"
	}
	return ""
}

// try opens and closes a connection, and says what went wrong in the vocabulary of the login flow. Whatever the driver
// said is left out unless it is one of this package's own errors: a connection error can quote the connection string.
func (d *Driver) try(ctx context.Context, target config.Database, user, pass string) error {
	database := ""
	if len(target.Databases) > 0 {
		database = target.Databases[0]
	}
	err := d.open(ctx, target, dbexec.Credentials{Username: user, Password: pass}, database)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, dbexec.ErrBadCredentials):
		return fmt.Errorf("%w: the database refused that username or password", site.ErrBadCredentials)
	case errors.Is(err, dbexec.ErrUnreachable):
		return fmt.Errorf("%w: %s%s", site.ErrUnreachable, target.Name, unreachableHint(err))
	case errors.Is(err, dbexec.ErrTimeout):
		return fmt.Errorf("%w: connecting to %s timed out", site.ErrUnreachable, target.Name)
	case errors.Is(err, dbexec.ErrLocalAddress):
		return fmt.Errorf("%w: %v", site.ErrLoginRejected, dbexec.ErrLocalAddress)
	case errors.Is(err, dbexec.ErrDatabaseNotAllowed):
		return fmt.Errorf("%w: %s lists databases (%s) and the first one could not be used: check databases in the configuration", site.ErrLoginRejected, target.Name, strings.Join(target.Databases, ", "))
	}
	return fmt.Errorf("%w: the database could not be opened", site.ErrLoginRejected)
}
