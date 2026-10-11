// Package keyring manages the short-lived OpenPGP key pairs used to protect credentials in transit.
//
// A key pair may serve at most MaxUses requests and live at most MaxAge; afterwards a new one is generated. Keys are
// kept in memory only (see MemoryPool): a private key on disk would be a secret the vault does not protect.
package keyring

import (
	"bytes"
	"encoding/hex"
	"io"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// Key is a usable key pair handed out by Acquire.
type Key struct {
	ID     string
	Entity *openpgp.Entity
	Uses   int // uses including this one
}

// PublicKeyBinary is the transferable public key in binary OpenPGP packet form.
func (k *Key) PublicKeyBinary() ([]byte, error) {
	var buf bytes.Buffer
	if err := k.Entity.Serialize(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Fingerprint is the upper-case hex fingerprint of the primary key.
func (k *Key) Fingerprint() string {
	return strings.ToUpper(hex.EncodeToString(k.Entity.PrimaryKey.Fingerprint))
}

// Decrypt decrypts an ASCII-armored (or raw binary) OpenPGP message.
func (k *Key) Decrypt(msg []byte) ([]byte, error) {
	var r io.Reader = bytes.NewReader(msg)
	if bytes.HasPrefix(bytes.TrimSpace(msg), []byte("-----BEGIN")) {
		blk, err := armor.Decode(bytes.NewReader(msg))
		if err != nil {
			return nil, err
		}
		r = blk.Body
	}
	md, err := openpgp.ReadMessage(r, openpgp.EntityList{k.Entity}, nil, nil)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(md.UnverifiedBody, 1<<20))
}
