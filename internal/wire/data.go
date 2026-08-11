package wire

import (
	"errors"
	"sync"
)

const (
	// ChanIDLen is the length of the blinded channel identifier.
	ChanIDLen = 32

	flagMore = 0x01

	// MaxChunk is how much ciphertext fits in a single DATA cell after the
	// channel id and the fragment flags.
	MaxChunk = MaxPayload - ChanIDLen - 1
)

var (
	// ErrBadData is returned for a malformed DATA payload.
	ErrBadData = errors.New("wire: malformed data payload")
	// ErrReassemblyLimit is returned when a peer tries to make us buffer
	// an unbounded amount of fragments.
	ErrReassemblyLimit = errors.New("wire: reassembly limit exceeded")
)

// SplitData fragments an opaque blob into DATA cell payloads. The relay sees
// the channel id and the fragment flag; it never sees where a message begins
// or ends beyond that, and it never reassembles anything.
func SplitData(chanID [ChanIDLen]byte, blob []byte) ([][]byte, error) {
	if len(blob) == 0 {
		return nil, ErrBadData
	}
	var out [][]byte
	for off := 0; off < len(blob); off += MaxChunk {
		end := off + MaxChunk
		if end > len(blob) {
			end = len(blob)
		}
		payload := make([]byte, 0, ChanIDLen+1+(end-off))
		payload = append(payload, chanID[:]...)
		var flags byte
		if end < len(blob) {
			flags |= flagMore
		}
		payload = append(payload, flags)
		payload = append(payload, blob[off:end]...)
		out = append(out, payload)
	}
	return out, nil
}

// ParseData decodes a DATA cell payload.
func ParseData(payload []byte) (chanID [ChanIDLen]byte, more bool, chunk []byte, err error) {
	if len(payload) < ChanIDLen+1 {
		return chanID, false, nil, ErrBadData
	}
	copy(chanID[:], payload[:ChanIDLen])
	more = payload[ChanIDLen]&flagMore != 0
	chunk = payload[ChanIDLen+1:]
	return chanID, more, chunk, nil
}

// Reassembler rebuilds fragmented blobs per channel. It is bounded: a peer
// cannot make it allocate more than max bytes for any single channel.
type Reassembler struct {
	mu  sync.Mutex
	buf map[[ChanIDLen]byte][]byte
	max int
}

// NewReassembler returns a Reassembler that refuses to buffer more than max
// bytes for a single in-flight message.
func NewReassembler(max int) *Reassembler {
	if max <= 0 {
		max = 256 << 10
	}
	return &Reassembler{buf: make(map[[ChanIDLen]byte][]byte), max: max}
}

// Push feeds one fragment. It returns a complete blob, or nil while the
// message is still incomplete.
func (r *Reassembler) Push(chanID [ChanIDLen]byte, more bool, chunk []byte) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	cur := r.buf[chanID]
	if len(cur)+len(chunk) > r.max {
		delete(r.buf, chanID)
		return nil, ErrReassemblyLimit
	}
	cur = append(cur, chunk...)
	if more {
		r.buf[chanID] = cur
		return nil, nil
	}
	delete(r.buf, chanID)
	return cur, nil
}

// Forget drops any partial state for a channel (used on PART).
func (r *Reassembler) Forget(chanID [ChanIDLen]byte) {
	r.mu.Lock()
	delete(r.buf, chanID)
	r.mu.Unlock()
}
