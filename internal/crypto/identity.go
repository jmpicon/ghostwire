// Package crypto holds ghostwire's key derivation, channel sealing and
// message authentication. The relay never touches anything in here.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"errors"

	"golang.org/x/crypto/blake2b"
)

// b32 is lowercase RFC4648 without padding: onion-address flavoured, easy to
// read aloud over a voice channel when you verify a fingerprint out of band.
var b32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// ErrBadSeed is returned when an identity seed has the wrong length.
var ErrBadSeed = errors.New("crypto: identity seed must be 32 bytes")

// Identity is an Ed25519 keypair. There is no registration, no server-side
// account and no directory: an identity is created locally and is only ever
// seen by people who already hold the channel passphrase.
//
// The default lifecycle is ephemeral — generated at startup, destroyed at
// exit, never written to disk.
type Identity struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

// NewIdentity generates a fresh ephemeral identity.
func NewIdentity() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Identity{pub: pub, priv: priv}, nil
}

// IdentityFromSeed rebuilds a persistent identity from a 32-byte seed.
func IdentityFromSeed(seed []byte) (*Identity, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, ErrBadSeed
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &Identity{pub: priv.Public().(ed25519.PublicKey), priv: priv}, nil
}

// Seed returns the 32-byte private seed. Handle it like plutonium.
func (i *Identity) Seed() []byte { return i.priv.Seed() }

// Public returns the Ed25519 public key.
func (i *Identity) Public() ed25519.PublicKey { return i.pub }

// Sign authenticates msg with the identity key.
func (i *Identity) Sign(msg []byte) []byte { return ed25519.Sign(i.priv, msg) }

// Fingerprint is the human-facing identifier: 16 base32 chars derived from
// the public key. Nicknames are cosmetic and forgeable; the fingerprint is not.
func (i *Identity) Fingerprint() string { return Fingerprint(i.pub) }

// Fingerprint derives the display fingerprint of any public key.
func Fingerprint(pub []byte) string {
	h := blake2b.Sum256(append([]byte("ghostwire/v1/fingerprint|"), pub...))
	return b32.EncodeToString(h[:10])
}

// Short is the 8-char form shown next to every nickname in the UI.
func Short(fp string) string {
	if len(fp) <= 8 {
		return fp
	}
	return fp[:8]
}

// Zeroize wipes the private key material in place.
func (i *Identity) Zeroize() {
	if i == nil {
		return
	}
	wipe(i.priv)
	i.priv = nil
	i.pub = nil
}

func wipe(b []byte) {
	for j := range b {
		b[j] = 0
	}
	// Defeat a compiler that decides the writes above are dead stores.
	_ = subtle.ConstantTimeCompare(b, b)
}
