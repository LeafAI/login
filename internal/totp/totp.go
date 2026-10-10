// Package totp implements RFC 6238 time-based one-time codes (HMAC-SHA1, RFC 4226 truncation) with a configurable
// period, in particular long periods such as 8 hours. It is used as a second factor for sealing credentials in the
// login page: the code never travels, it only becomes key material in the browser and on the server.
//
// A long-period code is a weak secret on its own (an 8-digit code has about 26.6 bits), so the seal layer always
// combines it with the 256-bit one-shot password and stretches it; the code adds a factor that is held in the
// person's authenticator and is not in any message.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238's default and what authenticators implement; the seal does not rely on its collision resistance
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// SecretSize is the size of a generated secret: 160 bits, the minimum RFC 4226 recommends.
	SecretSize = 20
	// MinPeriod and MaxPeriod bound the period a configuration may ask for.
	MinPeriod = 30 * time.Second
	MaxPeriod = 7 * 24 * time.Hour
)

// Settings are the validated parameters of a code.
type Settings struct {
	Period time.Duration
	Digits int
}

// ParseSettings validates a period and a digit count.
func ParseSettings(period time.Duration, digits int) (Settings, error) {
	if period < MinPeriod || period > MaxPeriod {
		return Settings{}, fmt.Errorf("totp period %s is out of range (%s to %s)", period, MinPeriod, MaxPeriod)
	}
	if digits < 6 || digits > 8 {
		return Settings{}, fmt.Errorf("totp digits %d is out of range (6 to 8)", digits)
	}
	return Settings{Period: period, Digits: digits}, nil
}

// Code returns the code of the window that contains t. The counter is floor(unix / period), as in RFC 6238.
func Code(secret []byte, t time.Time, period time.Duration, digits int) string {
	counter := uint64(t.Unix()) / uint64(period/time.Second)
	return hotp(secret, counter, digits)
}

func hotp(secret []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}

// NewSecret returns a fresh random secret.
func NewSecret() ([]byte, error) {
	s := make([]byte, SecretSize)
	if _, err := io.ReadFull(rand.Reader, s); err != nil {
		return nil, fmt.Errorf("totp: random secret: %w", err)
	}
	return s, nil
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// FormatSecret is the text form of a secret that authenticators accept: unpadded base32.
func FormatSecret(secret []byte) string { return b32.EncodeToString(secret) }

// ParseSecret reads the text form, tolerating what people paste: spaces, dashes, lower case and "=" padding.
func ParseSecret(text string) ([]byte, error) {
	clean := strings.NewReplacer(" ", "", "-", "", "=", "", "\n", "", "\r", "", "\t", "").Replace(strings.ToUpper(text))
	if clean == "" {
		return nil, fmt.Errorf("totp: the secret is empty")
	}
	b, err := b32.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("totp: the secret is not base32: %w", err)
	}
	if len(b) < 10 {
		return nil, fmt.Errorf("totp: the secret is %d bytes, far too short", len(b))
	}
	return b, nil
}

// URI is the otpauth:// URI an authenticator imports (usually through a QR code).
func URI(secret []byte, issuer, account string, period time.Duration, digits int) string {
	q := url.Values{}
	q.Set("secret", FormatSecret(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(digits))
	q.Set("period", fmt.Sprint(int64(period/time.Second)))
	// url.Values.Encode escapes spaces as "+", which not every authenticator reads back as a space.
	enc := strings.ReplaceAll(q.Encode(), "+", "%20")
	return "otpauth://totp/" + url.PathEscape(issuer) + ":" + url.PathEscape(account) + "?" + enc
}

// MaxCandidates bounds how many codes a span may produce: the guess space of an attacker, and the work of a server.
const MaxCandidates = 8

// CandidatesBetween returns the codes of every window that the span [from, to] touches, in time order and without
// duplicates. A code is read in one window and used in a later one (a link is opened minutes after it was made), so a
// server tries all of them. The span is bounded to MaxCandidates windows, keeping the ones nearest to "to".
func CandidatesBetween(secret []byte, from, to time.Time, period time.Duration, digits int) []string {
	if from.After(to) {
		from, to = to, from
	}
	secs := int64(period / time.Second)
	first, last := from.Unix()/secs, to.Unix()/secs
	if last-first+1 > MaxCandidates {
		first = last - MaxCandidates + 1
	}
	var out []string
	seen := map[string]bool{}
	for w := first; w <= last; w++ {
		c := hotp(secret, uint64(w), digits)
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

// SaveSecret writes a new secret to path (0600, directory 0700). It refuses to overwrite: replacing a secret that has
// already been registered in an authenticator would silently lock people out.
func SaveSecret(path string, secret []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("totp: create %s: %w", filepath.Dir(path), err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("totp: %s already exists; refusing to replace a secret that may be registered in an authenticator", path)
		}
		return fmt.Errorf("totp: write %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(FormatSecret(secret) + "\n"); err != nil {
		return fmt.Errorf("totp: write %s: %w", path, err)
	}
	return nil
}

// LoadSecret reads a secret file. A file that other users can read is refused: the secret may already be exposed.
func LoadSecret(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("totp: %w", err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("totp: %s is readable by other users (mode %v); run chmod 600 on it, or make a new secret if it may have been exposed", path, st.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("totp: %w", err)
	}
	return ParseSecret(string(b))
}

// Source is a secret with its settings: what the server and the command line use to get codes.
type Source struct {
	Secret   []byte
	Settings Settings
}

// Code is the code of the window containing t.
func (s *Source) Code(t time.Time) string {
	return Code(s.Secret, t, s.Settings.Period, s.Settings.Digits)
}

// Digits is the length of a code.
func (s *Source) Digits() int { return s.Settings.Digits }

// Window is CandidatesBetween with the source's settings.
func (s *Source) Window(from, to time.Time) []string {
	return CandidatesBetween(s.Secret, from, to, s.Settings.Period, s.Settings.Digits)
}
