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
	Site        string
	Mode        string // login | totp | custom
	N           int
	APIBase     string // https://tunnel.example/<token>
	PublicKey   []byte // binary OpenPGP public key
	Fingerprint string
	Fields      []Field // only for mode custom
}

// Link returns the URL (page base + fragment) the human clicks.
func Link(pageURL string, r Round) string {
	enc := base64.RawURLEncoding
	v := url.Values{}
	v.Set("v", "1")
	v.Set("site", r.Site)
	v.Set("mode", r.Mode)
	v.Set("round", fmt.Sprint(r.N))
	v.Set("u", r.APIBase)
	v.Set("k", enc.EncodeToString(r.PublicKey))
	v.Set("f", r.Fingerprint)
	if r.Mode == "custom" {
		b, _ := json.Marshal(r.Fields)
		v.Set("fields", enc.EncodeToString(b))
	}
	return strings.TrimRight(pageURL, "#") + "#" + v.Encode()
}
