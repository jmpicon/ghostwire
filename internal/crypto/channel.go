package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	// EpochSeconds is the channel key rotation period. Every hour the whole
	// channel silently moves to a fresh symmetric key derived from the
	// master secret. A key scraped out of a process's RAM stops working at
	// the epoch boundary.
	EpochSeconds = 3600

	// Argon2id parameters for turning a human passphrase into a channel
	// master key. Tuned so that a wordlist attacker pays ~64 MiB and real
	// CPU time per guess.
	argonTime    = 3
	argonMemKiB  = 64 * 1024
	argonThreads = 4

	// KeyLen is the symmetric key size in bytes.
	KeyLen = 32
)

// ErrOpen is returned when a ciphertext does not authenticate under any
// acceptable epoch key. Wrong passphrase, wrong channel, or tampering — the
// three are deliberately indistinguishable.
var ErrOpen = errors.New("crypto: cannot open sealed payload")

// ErrZeroized is returned when a channel is used after its key was destroyed.
var ErrZeroized = errors.New("crypto: channel key has been destroyed")

// Channel is a symmetric channel context derived from (name, passphrase).
//
// There is no channel registry anywhere. Two people who type the same name
// and the same passphrase land in the same channel; nobody else can even
// enumerate that the channel exists, because the relay only ever sees ID(),
// a blinded 32-byte tag with no relationship to the channel name that a
// dictionary attack could exploit without first breaking Argon2id.
//
// Zeroize can race with an in-flight Seal or Open — /part and /panic exist
// precisely to be used in a hurry — so the master key is guarded. Readers take
// the read lock; the wipe takes the write lock and marks the channel dead.
type Channel struct {
	Name string
	id   [32]byte

	mu     sync.RWMutex
	master [KeyLen]byte
	dead   bool
}

// NormalizeChannel canonicalises a channel name so that "#Ops", "ops" and
// " #ops " derive the same key.
func NormalizeChannel(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.TrimLeft(n, "#")
	return "#" + n
}

// DeriveChannel turns a name and a passphrase into a channel context.
// This is intentionally slow.
func DeriveChannel(name, passphrase string) *Channel {
	n := NormalizeChannel(name)
	salt := blake2b.Sum256([]byte("ghostwire/v1/channel-salt|" + n))
	m := argon2.IDKey([]byte(passphrase), salt[:16], argonTime, argonMemKiB, argonThreads, KeyLen)

	c := &Channel{Name: n}
	copy(c.master[:], m)
	wipe(m)
	c.id = derive(c.master, "channel-id")
	return c
}

// ID is the blinded channel identifier sent to the relay in the clear. It is
// the only thing the relay learns, and it is not reversible to the name.
func (c *Channel) ID() [32]byte { return c.id }

// Epoch returns the key epoch for a wall-clock instant.
func Epoch(t time.Time) uint64 { return uint64(t.Unix()) / EpochSeconds }

func derive(key [KeyLen]byte, label string) [32]byte {
	h, err := blake2b.New256(key[:])
	if err != nil {
		panic("ghostwire: blake2b: " + err.Error())
	}
	h.Write([]byte("ghostwire/v1/" + label))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// epochKey must be called with c.mu held for reading.
func (c *Channel) epochKey(e uint64) [KeyLen]byte {
	var info [8]byte
	binary.BigEndian.PutUint64(info[:], e)
	r := hkdf.New(sha256.New, c.master[:], c.id[:],
		append([]byte("ghostwire/v1/epoch"), info[:]...))
	var k [KeyLen]byte
	if _, err := io.ReadFull(r, k[:]); err != nil {
		panic("ghostwire: hkdf: " + err.Error())
	}
	return k
}

func (c *Channel) aad(e uint64) []byte {
	a := make([]byte, 0, 32+8)
	a = append(a, c.id[:]...)
	var eb [8]byte
	binary.BigEndian.PutUint64(eb[:], e)
	return append(a, eb[:]...)
}

// Seal encrypts a plaintext for the epoch containing now. Output is
// nonce(24) || XChaCha20-Poly1305 ciphertext.
func (c *Channel) Seal(plaintext []byte, now time.Time) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.dead {
		return nil, ErrZeroized
	}

	e := Epoch(now)
	k := c.epochKey(e)
	defer wipeArr(&k)

	aead, err := chacha20poly1305.NewX(k[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, c.aad(e)), nil
}

// Open decrypts a payload, tolerating one epoch of clock skew in either
// direction so that an hourly rotation never drops a message mid-boundary.
func (c *Channel) Open(sealed []byte, now time.Time) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.dead {
		return nil, ErrZeroized
	}
	if len(sealed) < chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead {
		return nil, ErrOpen
	}
	nonce := sealed[:chacha20poly1305.NonceSizeX]
	ct := sealed[chacha20poly1305.NonceSizeX:]

	e := Epoch(now)
	candidates := []uint64{e, e + 1}
	if e > 0 {
		candidates = append(candidates, e-1)
	}
	for _, cand := range candidates {
		k := c.epochKey(cand)
		aead, err := chacha20poly1305.NewX(k[:])
		wipeArr(&k)
		if err != nil {
			continue
		}
		if pt, err := aead.Open(nil, nonce, ct, c.aad(cand)); err == nil {
			return pt, nil
		}
	}
	return nil, ErrOpen
}

// Zeroize wipes the channel master secret and permanently retires the
// channel. Any concurrent Seal or Open either completed before the wipe or
// fails with ErrZeroized; neither can read a half-erased key.
func (c *Channel) Zeroize() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	wipeArr(&c.master)
	c.dead = true
}

func wipeArr(k *[KeyLen]byte) {
	for i := range k {
		k[i] = 0
	}
}
