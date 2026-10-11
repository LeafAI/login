// Package web embeds the trusted static login page and builds per-round links to it.
package web

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/LeafAI/securl/internal/seal"
)

//go:embed static/*
var static embed.FS

// WriteTo writes the static page (index.html, login.js, openpgp.min.js) into dir.
func WriteTo(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	ents, err := static.ReadDir("static")
	if err != nil {
		return err
	}
	for _, e := range ents {
		b, _ := static.ReadFile("static/" + e.Name())
		if err := os.WriteFile(filepath.Join(dir, e.Name()), b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// Checksums returns the SHA-256 of every embedded page file, in `sha256sum` format ("<hex>  <name>"),
// sorted by name. The same sums are published as SHA256SUMS next to the hosted page.
func Checksums() []string {
	ents, _ := static.ReadDir("static")
	var out []string
	for _, e := range ents {
		b, _ := static.ReadFile("static/" + e.Name())
		sum := sha256.Sum256(b)
		out = append(out, hex.EncodeToString(sum[:])+"  "+e.Name())
	}
	return out
}

// Field is a custom form field carried in the link (mode "custom").
type Field struct {
	Name   string `json:"name"`
	Label  string `json:"label"`
	Secret bool   `json:"secret,omitempty"`
	Image  string `json:"image,omitempty"` // data:image/...;base64,... shown above the input
}

// Round is everything the page needs for one authentication round.
type Round struct {
	Site         string
	Mode         string // login | totp | custom
	N            int
	APIBase      string // https://tunnel.example/<token>
	PublicKey    []byte // binary OpenPGP public key
	Fingerprint  string
	Password     []byte // the round's one-shot seal password (package seal); the page seals the submission under it
	FactorDigits int    // when > 0 the page also asks for the sealing code (this many digits) and seals with it

	// LinkCodes, when not empty, are the candidate codes of the unlock factor (the long-period TOTP). The link then does
	// not carry the site, the tunnel address and the one-shot password in the clear: they are encrypted, and the page
	// needs the person to type the unlock code (LinkDigits digits) to read them.
	LinkCodes  []string
	LinkDigits int

	Fields []Field // only for mode custom
}

// MaxSiteLen is how much of the site name the page keeps. The seal binds the site name, so the server must bind
// exactly what the page binds: both cut it to this length (a legal host name can be up to 253 characters).
const MaxSiteLen = 200

// BoundSite is the site name as the page and the seal see it.
func BoundSite(site string) string {
	if len(site) > MaxSiteLen {
		return site[:MaxSiteLen]
	}
	return site
}

// LinkVersion is the version of the link and submission format. Version 2 adds the one-shot password "s" and the
// sealed envelope; a page that does not know it refuses the link, and the server refuses unsealed submissions, so
// the two sides can never silently fall back to the previous, single-layer protocol.
const LinkVersion = "2"

// Link returns the URL (page base + fragment) the human clicks. It panics if the link was asked to be encrypted and
// cannot be: a link must never silently lose that protection. Callers that can report an error use LinkChecked.
func Link(pageURL string, r Round) string {
	l, err := LinkChecked(pageURL, r)
	if err != nil {
		panic("web.Link: " + err.Error())
	}
	return l
}

// LinkChecked builds the link, or says why it cannot. When encryption is requested (LinkDigits > 0) and impossible, it
// is an error, never a plain link: the person would believe the parameters are hidden.
func LinkChecked(pageURL string, r Round) (string, error) {
	enc := base64.RawURLEncoding
	v := url.Values{}
	v.Set("v", LinkVersion)
	v.Set("mode", r.Mode)
	v.Set("round", fmt.Sprint(r.N))
	v.Set("k", enc.EncodeToString(r.PublicKey))
	v.Set("f", r.Fingerprint)
	if r.FactorDigits > 0 {
		v.Set("t", fmt.Sprint(r.FactorDigits))
	}
	if r.Mode == "custom" {
		b, _ := json.Marshal(r.Fields)
		v.Set("fields", enc.EncodeToString(b))
	}
	if r.LinkDigits > 0 || len(r.LinkCodes) > 0 {
		blob, err := seal.SealLink(r.LinkCodes, seal.LinkContext{Fingerprint: r.Fingerprint, Mode: r.Mode, Round: r.N},
			seal.LinkParams{Site: BoundSite(r.Site), API: r.APIBase, Password: r.Password})
		if err != nil {
			return "", fmt.Errorf("encrypting the link parameters: %w", err)
		}
		if r.LinkDigits < 6 || r.LinkDigits > 8 {
			return "", fmt.Errorf("the unlock code length %d is not 6, 7 or 8", r.LinkDigits)
		}
		v.Set("e", blob)
		v.Set("c", fmt.Sprint(r.LinkDigits))
	} else {
		v.Set("site", BoundSite(r.Site))
		v.Set("u", r.APIBase)
		v.Set("s", enc.EncodeToString(r.Password))
	}
	return strings.TrimRight(pageURL, "#") + "#" + v.Encode(), nil
}
