package crypto

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"time"

	"golang.org/x/crypto/blake2b"
)

// Kind classifies an inner (already decrypted) message.
type Kind uint8

const (
	KindMsg      Kind = 1 // ordinary channel line
	KindAction   Kind = 2 // /me
	KindPresence Kind = 3 // "join", "part", "nick <new>"
)

const (
	msgVersion = 0x01

	// TimeGranularity is how coarsely timestamps are recorded. Nothing in
	// ghostwire needs millisecond precision, and a precise clock is a
	// fingerprint.
	TimeGranularity = 10 * time.Second

	maxNick = 32
	maxBody = 8 << 10
)

var (
	// ErrBadMessage is returned for a structurally invalid inner message.
	ErrBadMessage = errors.New("crypto: malformed message")
	// ErrBadSignature is returned when the sender signature does not verify.
	ErrBadSignature = errors.New("crypto: bad signature")
	// ErrStale is returned when a message falls outside the freshness window.
	ErrStale = errors.New("crypto: message outside freshness window")
)

// Message is the plaintext that lives inside a sealed channel payload.
//
// The signature covers everything: whoever holds the channel passphrase can
// read the traffic, but cannot forge a line as somebody else's fingerprint.
type Message struct {
	Kind   Kind
	Sender ed25519.PublicKey
	Nick   string
	Sent   time.Time
	Body   string
}

// Fingerprint of the sender.
func (m *Message) Fingerprint() string { return Fingerprint(m.Sender) }

// Marshal serialises and signs the message with id.
func (m *Message) Marshal(id *Identity) ([]byte, error) {
	nick := m.Nick
	if len(nick) > maxNick {
		nick = nick[:maxNick]
	}
	if len(m.Body) > maxBody {
		return nil, ErrBadMessage
	}
	ts := m.Sent.Truncate(TimeGranularity).Unix()
	if ts < 0 {
		return nil, ErrBadMessage
	}

	buf := make([]byte, 0, 43+len(nick)+2+len(m.Body)+ed25519.SignatureSize)
	buf = append(buf, msgVersion, byte(m.Kind))
	buf = append(buf, id.Public()...)
	var tsb [8]byte
	binary.BigEndian.PutUint64(tsb[:], uint64(ts))
	buf = append(buf, tsb[:]...)
	buf = append(buf, byte(len(nick)))
	buf = append(buf, nick...)
	var bl [2]byte
	binary.BigEndian.PutUint16(bl[:], uint16(len(m.Body)))
	buf = append(buf, bl[:]...)
	buf = append(buf, m.Body...)

	return append(buf, id.Sign(buf)...), nil
}

// ParseMessage decodes, verifies and freshness-checks an inner message.
func ParseMessage(b []byte, now time.Time, skew time.Duration) (*Message, error) {
	const fixed = 1 + 1 + ed25519.PublicKeySize + 8 + 1
	if len(b) < fixed+2+ed25519.SignatureSize {
		return nil, ErrBadMessage
	}
	if b[0] != msgVersion {
		return nil, ErrBadMessage
	}

	signed := b[:len(b)-ed25519.SignatureSize]
	sig := b[len(b)-ed25519.SignatureSize:]

	off := 1
	kind := Kind(b[off])
	off++
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(pub, b[off:off+ed25519.PublicKeySize])
	off += ed25519.PublicKeySize
	ts := int64(binary.BigEndian.Uint64(b[off : off+8]))
	off += 8

	nickLen := int(b[off])
	off++
	if off+nickLen+2 > len(signed) {
		return nil, ErrBadMessage
	}
	nick := string(b[off : off+nickLen])
	off += nickLen

	bodyLen := int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	if off+bodyLen != len(signed) {
		return nil, ErrBadMessage
	}
	body := string(b[off : off+bodyLen])

	if !ed25519.Verify(pub, signed, sig) {
		return nil, ErrBadSignature
	}
	sent := time.Unix(ts, 0).UTC()
	if skew > 0 {
		if d := now.Sub(sent); d > skew || d < -skew {
			return nil, ErrStale
		}
	}
	return &Message{Kind: kind, Sender: pub, Nick: nick, Sent: sent, Body: body}, nil
}

// ReplayID is a stable identifier for a sealed payload, used to drop
// duplicates that a hostile relay re-injects.
func ReplayID(sealed []byte) [32]byte {
	return blake2b.Sum256(append([]byte("ghostwire/v1/replay|"), sealed...))
}
