// Package relay implements gwd, the blind rendezvous server.
//
// What the relay knows:
//   - that some anonymous Tor circuit is connected
//   - a set of opaque 32-byte channel ids that circuit subscribed to
//   - that fixed-size cells arrived and were fanned out
//
// What the relay cannot know, by construction:
//   - who you are (no accounts, no keys, no handshake identity)
//   - where you are (the only transport is an onion service)
//   - what channel names those ids correspond to
//   - anything about message content, length, or boundaries
//
// It keeps no disk state. It writes no per-connection logs. Restarting it
// destroys everything it ever held.
package relay

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jmpicon/ghostwire/internal/wire"
)

// Options tunes the relay's resource limits and cover-traffic behaviour.
type Options struct {
	MaxConns        int
	MaxChansPerConn int
	OutQueue        int
	CellsPerSecond  float64
	CellBurst       float64
	IdleTimeout     time.Duration
	WriteTimeout    time.Duration
	NoiseMean       time.Duration
}

// DefaultOptions returns sane limits for a relay on a small VPS.
func DefaultOptions() Options {
	return Options{
		MaxConns:        512,
		MaxChansPerConn: 16,
		OutQueue:        256,
		CellsPerSecond:  64,
		CellBurst:       256,
		IdleTimeout:     5 * time.Minute,
		WriteTimeout:    30 * time.Second,
		NoiseMean:       20 * time.Second,
	}
}

func (o *Options) normalize() {
	d := DefaultOptions()
	if o.MaxConns <= 0 {
		o.MaxConns = d.MaxConns
	}
	if o.MaxChansPerConn <= 0 {
		o.MaxChansPerConn = d.MaxChansPerConn
	}
	if o.OutQueue <= 0 {
		o.OutQueue = d.OutQueue
	}
	if o.CellsPerSecond <= 0 {
		o.CellsPerSecond = d.CellsPerSecond
	}
	if o.CellBurst <= 0 {
		o.CellBurst = d.CellBurst
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = d.IdleTimeout
	}
	if o.WriteTimeout <= 0 {
		o.WriteTimeout = d.WriteTimeout
	}
	if o.NoiseMean < 0 {
		o.NoiseMean = d.NoiseMean
	}
}

// Stats are aggregate counters. They are deliberately global: there is no
// per-connection and no per-channel accounting to leak.
type Stats struct {
	Conns    int64
	Channels int64
	CellsIn  uint64
	CellsOut uint64
	Dropped  uint64
}

// Relay is the blind fan-out hub.
type Relay struct {
	opts Options

	mu    sync.RWMutex
	chans map[[wire.ChanIDLen]byte]map[*conn]struct{}

	nconn    int64
	cellsIn  uint64
	cellsOut uint64
	dropped  uint64
}

// New builds a relay.
func New(opts Options) *Relay {
	opts.normalize()
	return &Relay{
		opts:  opts,
		chans: make(map[[wire.ChanIDLen]byte]map[*conn]struct{}),
	}
}

// Stats snapshots the aggregate counters.
func (r *Relay) Stats() Stats {
	r.mu.RLock()
	nch := len(r.chans)
	r.mu.RUnlock()
	return Stats{
		Conns:    atomic.LoadInt64(&r.nconn),
		Channels: int64(nch),
		CellsIn:  atomic.LoadUint64(&r.cellsIn),
		CellsOut: atomic.LoadUint64(&r.cellsOut),
		Dropped:  atomic.LoadUint64(&r.dropped),
	}
}

// Serve accepts connections until ctx is cancelled or ln fails.
func (r *Relay) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		nc, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}

		if atomic.AddInt64(&r.nconn, 1) > int64(r.opts.MaxConns) {
			atomic.AddInt64(&r.nconn, -1)
			_ = nc.Close()
			continue
		}

		c := newConn(r, nc)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer atomic.AddInt64(&r.nconn, -1)
			c.serve(ctx)
		}()
	}
}

func (r *Relay) subscribe(c *conn, id [wire.ChanIDLen]byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := c.subs[id]; ok {
		return true
	}
	if len(c.subs) >= r.opts.MaxChansPerConn {
		return false
	}
	set := r.chans[id]
	if set == nil {
		set = make(map[*conn]struct{})
		r.chans[id] = set
	}
	set[c] = struct{}{}
	c.subs[id] = struct{}{}
	return true
}

func (r *Relay) unsubscribe(c *conn, id [wire.ChanIDLen]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.unsubLocked(c, id)
}

func (r *Relay) unsubLocked(c *conn, id [wire.ChanIDLen]byte) {
	if set := r.chans[id]; set != nil {
		delete(set, c)
		if len(set) == 0 {
			delete(r.chans, id)
		}
	}
	delete(c.subs, id)
}

func (r *Relay) unsubscribeAll(c *conn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id := range c.subs {
		r.unsubLocked(c, id)
	}
}

// fanout forwards a raw DATA cell to every subscriber of id, including the
// sender. Echoing to the sender is intentional: it equalises each connection's
// inbound and outbound rate, and it doubles as an end-to-end delivery receipt
// that costs the relay no extra state.
func (r *Relay) fanout(id [wire.ChanIDLen]byte, cell []byte) {
	r.mu.RLock()
	set := r.chans[id]
	targets := make([]*conn, 0, len(set))
	for c := range set {
		targets = append(targets, c)
	}
	r.mu.RUnlock()

	for _, c := range targets {
		if c.send(cell) {
			atomic.AddUint64(&r.cellsOut, 1)
		} else {
			atomic.AddUint64(&r.dropped, 1)
		}
	}
}
