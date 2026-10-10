package web_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
)

// The vendored library must be exactly the published release (npm openpgp@6.3.2, dist/openpgp.min.js).
func TestVendoredOpenPGPIsTheOfficialRelease(t *testing.T) {
	b, err := os.ReadFile("static/openpgp.min.js")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	const want = "e19bf4f04f34f24caded3ff3f3643099538b2674a0a94221e2faca75ac3e4aa1"
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("openpgp.min.js sha256 = %s, want %s (npm openpgp@6.3.2). If you upgraded it on purpose, re-verify against the npm tarball and update this value, THIRD_PARTY_NOTICES.md and the SRI hash.", got, want)
	}
}
