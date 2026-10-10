package seal

// Link layer: what is sent to DingTalk is not the link's parameters but an encrypted blob of them, and the person needs
// the first TOTP code (the long-period one, in their authenticator) to read it. The key fingerprint and the step stay
// in the clear on purpose: the person compares the key code with the message BEFORE typing anything, and that check is
// what protects against a forged link.
//
// A link may be opened some minutes after it was made, so the code that is valid when the server builds the link may not
// be the one valid when the person opens it. The blob therefore carries one "slot" per candidate code, each wrapping the
// same random 256-bit link key; the page tries them all with the code the person types.
//
//	stretched = PBKDF2-HMAC-SHA256(code, salt = SHA-256("login/link/v1|fingerprint|mode|round"), 200000, 32)
//	slotKey   = HKDF-SHA256(ikm = stretched, salt = SHA-256("login/link/v1"), info = "login/link/v1|slot|fingerprint|mode|round")
//	slot      = IV(12) || AES-256-GCM(slotKey, IV, linkKey, aad = "login/link/v1|slot|fingerprint|mode|round")   (60 bytes)
//	body      = IV(12) || AES-256-GCM(linkKey, IV, json(params), aad = "login/link/v1|body|fingerprint|mode|round")
//	blob      = "l1." + base64url(slotCount(1) || slot_1 || ... || slot_n || body)
//
// The salt cannot be random per link, because the page only has the blob and the code; it is bound to the key and the
// step instead, and the 200000 PBKDF2 iterations carry the work factor. A short code is weak against someone who has the
// blob (about 27 bits for 8 digits, 20 for 6): that is why the blob is not the only protection, the parameters it hides
// are useless without the GPG key that only the local machine holds.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/hkdf"
)

const (
	// LinkPrefix marks the format of an encrypted parameter blob.
	LinkPrefix = "l1."
	// MaxLinkSlots bounds the number of candidate codes a link carries: each costs 60 bytes in a URL fragment and a
	// PBKDF2 run in the browser.
	MaxLinkSlots = 4
	linkLabel    = "login/link/v1"
	slotSize     = ivSize + keySize + 16 // IV + wrapped 32-byte key + GCM tag
)

// LinkContext is what the encrypted parameters are bound to: things that stay in the clear in the link.
type LinkContext struct {
	Fingerprint string
	Mode        string
	Round       int
}

// LinkParams are the parameters that are hidden from the DingTalk message.
type LinkParams struct {
	Site     string `json:"site"`
	API      string `json:"u"`
	Password []byte `json:"s"` // the round's one-shot seal password
}

var errLink = errors.New("link parameters cannot be opened")

func (c LinkContext) text() string { return c.Fingerprint + "|" + c.Mode + "|" + strconv.Itoa(c.Round) }

func linkSalt(c LinkContext) []byte {
	s := sha256.Sum256([]byte(linkLabel + "|" + c.text()))
	return s[:]
}

func stretchLink(code string, c LinkContext) []byte {
	out, _ := pbkdf2.Key(sha256.New, code, linkSalt(c), FactorIterations, keySize)
	return out
}

func linkSlotKey(code string, c LinkContext) []byte {
	salt := sha256.Sum256([]byte(linkLabel))
	key := make([]byte, keySize)
	io.ReadFull(hkdf.New(sha256.New, stretchLink(code, c), salt[:], []byte(linkLabel+"|slot|"+c.text())), key)
	return key
}

func slotAAD(c LinkContext) []byte { return []byte(linkLabel + "|slot|" + c.text()) }
func bodyAAD(c LinkContext) []byte { return []byte(linkLabel + "|body|" + c.text()) }

func gcmFor(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("seal: random bytes: %w", err)
	}
	return b, nil
}

// SealLink encrypts the parameters under a fresh random link key and wraps that key once for each candidate code.
func SealLink(candidates []string, c LinkContext, p LinkParams) (string, error) {
	if len(candidates) == 0 || len(candidates) > MaxLinkSlots {
		return "", fmt.Errorf("seal: a link needs 1 to %d candidate codes, got %d", MaxLinkSlots, len(candidates))
	}
	if len(p.Password) != PasswordSize || p.API == "" || p.Site == "" {
		return "", errors.New("seal: link parameters are incomplete (site, api address and a 32-byte password are required)")
	}
	linkKey, err := randomBytes(keySize)
	if err != nil {
		return "", err
	}
	defer Wipe(linkKey)
	out := []byte{byte(len(candidates))}
	for _, code := range candidates {
		iv, err := randomBytes(ivSize)
		if err != nil {
			return "", err
		}
		gcm, err := gcmFor(linkSlotKey(code, c))
		if err != nil {
			return "", err
		}
		out = append(out, gcm.Seal(iv, iv, linkKey, slotAAD(c))...)
	}
	plain, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	iv, err := randomBytes(ivSize)
	if err != nil {
		return "", err
	}
	gcm, err := gcmFor(linkKey)
	if err != nil {
		return "", err
	}
	out = append(out, gcm.Seal(iv, iv, plain, bodyAAD(c))...)
	Wipe(plain)
	return LinkPrefix + base64.RawURLEncoding.EncodeToString(out), nil
}

// OpenLink decrypts the parameters with the code the person typed. It is the reference for what the page does.
func OpenLink(code string, c LinkContext, blob string) (LinkParams, error) {
	var zero LinkParams
	if !strings.HasPrefix(blob, LinkPrefix) {
		return zero, errLink
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(blob, LinkPrefix))
	if err != nil || len(raw) < 1 {
		return zero, errLink
	}
	n := int(raw[0])
	if n < 1 || n > MaxLinkSlots || len(raw) < 1+n*slotSize+ivSize+16 {
		return zero, errLink
	}
	gcm, err := gcmFor(linkSlotKey(code, c))
	if err != nil {
		return zero, errLink
	}
	var linkKey []byte
	for i := 0; i < n; i++ {
		slot := raw[1+i*slotSize : 1+(i+1)*slotSize]
		if k, err := gcm.Open(nil, slot[:ivSize], slot[ivSize:], slotAAD(c)); err == nil {
			linkKey = k
			break
		}
	}
	if linkKey == nil {
		return zero, errLink
	}
	defer Wipe(linkKey)
	body := raw[1+n*slotSize:]
	bg, err := gcmFor(linkKey)
	if err != nil {
		return zero, errLink
	}
	plain, err := bg.Open(nil, body[:ivSize], body[ivSize:], bodyAAD(c))
	if err != nil {
		return zero, errLink
	}
	defer Wipe(plain)
	var p LinkParams
	if err := json.Unmarshal(plain, &p); err != nil || len(p.Password) != PasswordSize || p.API == "" || p.Site == "" {
		return zero, errLink
	}
	return p, nil
}
