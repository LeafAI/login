// Package seal wraps a credential in AES-256-GCM under a random one-shot password before it is encrypted to the
// OpenPGP key. It is a second, independent layer: the OpenPGP layer remains the one that keeps the credential
// from the tunnel, and this layer makes sure that a flaw in one layer does not by itself expose the plaintext, and
// that a ciphertext cannot be replayed into another site, step or round.
//
// Wire format of a sealed value: "v1." + base64url(IV || ciphertext || tag), with a fresh random 12-byte IV.
//
// A seal may also require a second factor, a code that is in the person's authenticator and in no message (for
// example a long-period TOTP code). The code is short, so on its own it would be a weak secret; it is therefore never
// used alone. It is stretched and combined with the one-shot password:
//
//	stretched = PBKDF2-HMAC-SHA256(code, salt = one-shot password, 200000 iterations, 32 bytes)
//	key       = HKDF-SHA256(ikm = password || stretched, salt = SHA-256("login/seal/v2"),
//	                        info = "login/seal/v2|site|mode|round")
//
// and the format is "v2." + base64url(IV || ciphertext || tag). The two formats have different prefixes, labels and
// keys, so a seal of one kind never opens as the other and the factor cannot be skipped.
//
// The AES key is derived with HKDF-SHA256 from the one-shot password:
//
//	salt = SHA-256("login/seal/v1")      info = "login/seal/v1|site|mode|round"
//
// and the same context (site, mode, round, nonce) is the GCM additional data, so the context is bound twice.
// A browser reproduces all of this with WebCrypto (HKDF, AES-GCM); see internal/web/static/login.js.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/hkdf"
)

const (
	// Prefix marks the format version of a sealed value without a second factor.
	Prefix = "v1."
	// PrefixFactor marks a sealed value that also needs a second factor.
	PrefixFactor = "v2."
	// FactorIterations is the PBKDF2 cost of stretching the second factor. A short code is guessable, so every guess
	// must cost real work; the salt is the one-shot password, so nothing precomputed serves two rounds.
	FactorIterations = 200000
	maxFactorLen     = 64
	// PasswordSize is the size of a one-shot password: 256 bits.
	PasswordSize = 32
	ivSize       = 12
	keySize      = 32
	label        = "login/seal/v1"
	labelFactor  = "login/seal/v2"
)

// Context is what a sealed value is bound to.
type Context struct {
	Site  string
	Mode  string
	Round int
	Nonce string
}

// ErrOpen is returned for every failure to open a sealed value, whatever the cause, so that the answer does not
// tell an attacker which part was wrong.
var ErrOpen = errors.New("sealed value cannot be opened")

// NewPassword returns a fresh random one-shot password.
func NewPassword() ([]byte, error) {
	p := make([]byte, PasswordSize)
	if _, err := io.ReadFull(rand.Reader, p); err != nil {
		return nil, fmt.Errorf("seal: random password: %w", err)
	}
	return p, nil
}

// Wipe overwrites a password once it has been used.
func Wipe(p []byte) {
	for i := range p {
		p[i] = 0
	}
}

func info(c Context) []byte {
	return []byte(label + "|" + c.Site + "|" + c.Mode + "|" + strconv.Itoa(c.Round))
}

// aad is the GCM additional data: it includes the nonce, which key derivation does not.
func aad(c Context) []byte {
	return []byte(label + "|" + c.Site + "|" + c.Mode + "|" + strconv.Itoa(c.Round) + "|" + c.Nonce)
}

func deriveKey(password []byte, c Context) []byte {
	salt := sha256.Sum256([]byte(label))
	key := make([]byte, keySize)
	// hkdf.New only fails when asked for more than 255 hash blocks; 32 bytes is far below that.
	io.ReadFull(hkdf.New(sha256.New, password, salt[:], info(c)), key)
	return key
}

// stretch turns the second factor into 32 bytes of key material. The one-shot password is the salt.
func stretch(factor string, password []byte) []byte {
	// pbkdf2.Key fails only for an invalid hash or a length beyond the hash's limit; neither can happen here.
	out, _ := pbkdf2.Key(sha256.New, factor, password, FactorIterations, keySize)
	return out
}

func infoFactor(c Context) []byte {
	return []byte(labelFactor + "|" + c.Site + "|" + c.Mode + "|" + strconv.Itoa(c.Round))
}

func aadFactor(c Context) []byte {
	return []byte(labelFactor + "|" + c.Site + "|" + c.Mode + "|" + strconv.Itoa(c.Round) + "|" + c.Nonce)
}

func deriveKeyWithFactor(password []byte, factor string, c Context) []byte {
	salt := sha256.Sum256([]byte(labelFactor))
	ikm := append(append([]byte{}, password...), stretch(factor, password)...)
	key := make([]byte, keySize)
	io.ReadFull(hkdf.New(sha256.New, ikm, salt[:], infoFactor(c)), key)
	Wipe(ikm)
	return key
}

func newGCMFromKey(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func checkPassword(password []byte) error {
	if len(password) != PasswordSize {
		return fmt.Errorf("seal: the one-shot password must be %d bytes, got %d", PasswordSize, len(password))
	}
	return nil
}

// SealWithFactor is Seal for a login that also requires a second factor (the code).
func SealWithFactor(password []byte, factor string, c Context, plaintext []byte) (string, error) {
	if err := checkPassword(password); err != nil {
		return "", err
	}
	if factor == "" || len(factor) > maxFactorLen {
		return "", fmt.Errorf("seal: the second factor must be 1 to %d characters", maxFactorLen)
	}
	gcm, err := newGCMFromKey(deriveKeyWithFactor(password, factor, c))
	if err != nil {
		return "", err
	}
	iv := make([]byte, ivSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("seal: random IV: %w", err)
	}
	return PrefixFactor + base64.RawURLEncoding.EncodeToString(gcm.Seal(iv, iv, plaintext, aadFactor(c))), nil
}

// OpenWithFactor opens a seal that requires a second factor, trying each candidate code (the neighbouring window's code
// near a boundary). A plain seal, and any failure, is ErrOpen: when a factor is required the plain format is not
// accepted at all.
func OpenWithFactor(password []byte, candidates []string, c Context, sealed string) ([]byte, error) {
	if checkPassword(password) != nil || !strings.HasPrefix(sealed, PrefixFactor) {
		return nil, ErrOpen
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(sealed, PrefixFactor))
	if err != nil || len(raw) < ivSize+16 {
		return nil, ErrOpen
	}
	for _, factor := range candidates {
		if factor == "" || len(factor) > maxFactorLen {
			continue
		}
		gcm, err := newGCMFromKey(deriveKeyWithFactor(password, factor, c))
		if err != nil {
			continue
		}
		if plain, err := gcm.Open(nil, raw[:ivSize], raw[ivSize:], aadFactor(c)); err == nil {
			return plain, nil
		}
	}
	return nil, ErrOpen
}

func newGCM(password []byte, c Context) (cipher.AEAD, error) {
	if len(password) != PasswordSize {
		return nil, fmt.Errorf("seal: the one-shot password must be %d bytes, got %d", PasswordSize, len(password))
	}
	block, err := aes.NewCipher(deriveKey(password, c))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Seal encrypts and authenticates plaintext under the one-shot password, bound to c.
func Seal(password []byte, c Context, plaintext []byte) (string, error) {
	gcm, err := newGCM(password, c)
	if err != nil {
		return "", err
	}
	iv := make([]byte, ivSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("seal: random IV: %w", err)
	}
	out := gcm.Seal(iv, iv, plaintext, aad(c)) // IV || ciphertext || tag
	return Prefix + base64.RawURLEncoding.EncodeToString(out), nil
}

// Open verifies and decrypts a sealed value. Any problem (format, password, context, tampering) is ErrOpen.
func Open(password []byte, c Context, sealed string) ([]byte, error) {
	gcm, err := newGCM(password, c)
	if err != nil {
		return nil, ErrOpen
	}
	if !strings.HasPrefix(sealed, Prefix) {
		return nil, ErrOpen
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(sealed, Prefix))
	if err != nil || len(raw) < ivSize+gcm.Overhead() {
		return nil, ErrOpen
	}
	plain, err := gcm.Open(nil, raw[:ivSize], raw[ivSize:], aad(c))
	if err != nil {
		return nil, ErrOpen
	}
	return plain, nil
}
