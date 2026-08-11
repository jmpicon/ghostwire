// Package noise generates the timing used for cover traffic.
//
// Cover traffic only helps if its schedule is memoryless. A fixed 20s tick is
// trivially separable from real messages by a passive observer; an exponential
// inter-arrival time is not, because the resulting stream is a Poisson process
// and real messages injected into it are indistinguishable from the padding
// that surrounds them.
package noise

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"time"
)

// Float64 returns a uniform value in [0,1) from the CSPRNG. ghostwire never
// uses math/rand for anything that an adversary can observe.
func Float64() float64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A failing CSPRNG is not a recoverable condition for this program.
		panic("ghostwire: crypto/rand unavailable: " + err.Error())
	}
	return float64(binary.BigEndian.Uint64(b[:])>>11) / (1 << 53)
}

// Interval samples an exponential delay with the given mean, clamped so a
// pathological draw can neither hammer the relay nor stall for an hour.
func Interval(mean time.Duration) time.Duration {
	if mean <= 0 {
		return 0
	}
	u := Float64()
	if u < 1e-12 {
		u = 1e-12
	}
	d := time.Duration(-math.Log(u) * float64(mean))

	if min := mean / 8; d < min {
		d = min
	}
	if max := mean * 5; d > max {
		d = max
	}
	return d
}

// Jitter returns a uniform delay in [0,max), applied before sending a real
// message so that keystroke timing does not survive to the wire.
func Jitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	return time.Duration(Float64() * float64(max))
}
