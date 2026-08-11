package crypto

import (
	"sync"
	"time"
)

// ReplayGuard remembers recently accepted payloads so a malicious or
// compromised relay cannot resend an old ciphertext to fake activity.
type ReplayGuard struct {
	mu   sync.Mutex
	seen map[[32]byte]time.Time
	ttl  time.Duration
	max  int
}

// NewReplayGuard returns a guard that remembers payloads for ttl.
func NewReplayGuard(ttl time.Duration) *ReplayGuard {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &ReplayGuard{seen: make(map[[32]byte]time.Time), ttl: ttl, max: 8192}
}

// Seen records id and reports whether it had already been accepted.
func (g *ReplayGuard) Seen(id [32]byte, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, dup := g.seen[id]; dup {
		return true
	}
	if len(g.seen) >= g.max {
		g.sweep(now)
		if len(g.seen) >= g.max {
			g.seen = make(map[[32]byte]time.Time, g.max/2)
		}
	}
	g.seen[id] = now
	return false
}

func (g *ReplayGuard) sweep(now time.Time) {
	for k, t := range g.seen {
		if now.Sub(t) > g.ttl {
			delete(g.seen, k)
		}
	}
}
