// Package wire implements ghostwire's link framing.
//
// Everything that crosses the socket is a CELL: exactly 512 bytes, always.
// A cell carrying a one-character message and a cell carrying nothing but
// random padding are byte-for-byte indistinguishable to anyone watching the
// wire, including the relay operator and whoever runs the Tor exit-side of the
// rendezvous. Length is never a side channel because there is no length.
package wire

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

const (
	// Version is the protocol version carried in every cell header.
	Version = 0x01

	// CellSize is the invariant on-wire size of every cell.
	CellSize = 512

	// HeaderLen is version(1) + type(1) + payload length(2).
	HeaderLen = 4

	// MaxPayload is the usable bytes inside one cell.
	MaxPayload = CellSize - HeaderLen
)

// Type identifies the cell's purpose.
type Type uint8

const (
	// TypeNoise is cover traffic. It is deliberately value 0 so that a
	// zeroed buffer decodes as "nothing happened".
	TypeNoise Type = 0x00
	TypeHello Type = 0x01
	TypeJoin  Type = 0x02
	TypePart  Type = 0x03
	TypeData  Type = 0x04
	TypePing  Type = 0x05
	TypePong  Type = 0x06
	TypeBye   Type = 0x07
	TypeErr   Type = 0x08
)

func (t Type) String() string {
	switch t {
	case TypeNoise:
		return "NOISE"
	case TypeHello:
		return "HELLO"
	case TypeJoin:
		return "JOIN"
	case TypePart:
		return "PART"
	case TypeData:
		return "DATA"
	case TypePing:
		return "PING"
	case TypePong:
		return "PONG"
	case TypeBye:
		return "BYE"
	case TypeErr:
		return "ERR"
	default:
		return "UNKNOWN"
	}
}

var (
	// ErrBadVersion is returned for a cell whose version byte is unknown.
	ErrBadVersion = errors.New("wire: unknown protocol version")
	// ErrOversize is returned when a payload cannot fit in a cell.
	ErrOversize = errors.New("wire: payload exceeds cell capacity")
	// ErrShortCell is returned when a buffer is not exactly CellSize.
	ErrShortCell = errors.New("wire: buffer is not a whole cell")
)

// Marshal builds one cell. Unused bytes are filled with cryptographic random
// so that padding never compresses and never repeats.
func Marshal(t Type, payload []byte) ([]byte, error) {
	if len(payload) > MaxPayload {
		return nil, ErrOversize
	}
	cell := make([]byte, CellSize)
	cell[0] = Version
	cell[1] = byte(t)
	binary.BigEndian.PutUint16(cell[2:4], uint16(len(payload)))
	copy(cell[HeaderLen:], payload)
	if _, err := rand.Read(cell[HeaderLen+len(payload):]); err != nil {
		return nil, err
	}
	return cell, nil
}

// Noise builds a pure cover-traffic cell.
func Noise() ([]byte, error) { return Marshal(TypeNoise, nil) }

// Parse decodes exactly one cell.
func Parse(buf []byte) (Type, []byte, error) {
	if len(buf) != CellSize {
		return 0, nil, ErrShortCell
	}
	if buf[0] != Version {
		return 0, nil, ErrBadVersion
	}
	n := int(binary.BigEndian.Uint16(buf[2:4]))
	if n > MaxPayload {
		return 0, nil, ErrOversize
	}
	payload := make([]byte, n)
	copy(payload, buf[HeaderLen:HeaderLen+n])
	return Type(buf[1]), payload, nil
}

// Read pulls exactly one cell off r. It never returns a partial cell.
func Read(r io.Reader) (Type, []byte, error) {
	buf := make([]byte, CellSize)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return Parse(buf)
}
