package relay

import (
	"bufio"
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jmpicon/ghostwire/internal/noise"
	"github.com/jmpicon/ghostwire/internal/wire"
)

type conn struct {
	r  *Relay
	nc net.Conn

	out  chan []byte
	subs map[[wire.ChanIDLen]byte]struct{}

	bucket *bucket

	closeOnce sync.Once
	done      chan struct{}
}

func newConn(r *Relay, nc net.Conn) *conn {
	return &conn{
		r:      r,
		nc:     nc,
		out:    make(chan []byte, r.opts.OutQueue),
		subs:   make(map[[wire.ChanIDLen]byte]struct{}),
		bucket: newBucket(r.opts.CellsPerSecond, r.opts.CellBurst),
		done:   make(chan struct{}),
	}
}

// send queues a cell without ever blocking the fan-out path. A connection that
// cannot keep up loses cells rather than stalling the whole channel — the
// alternative is a trivial memory-exhaustion lever for any client.
func (c *conn) send(cell []byte) bool {
	select {
	case c.out <- cell:
		return true
	case <-c.done:
		return false
	default:
		return false
	}
}

func (c *conn) close() {
	c.closeOnce.Do(func() {
		close(c.done)
		_ = c.nc.Close()
	})
}

func (c *conn) serve(ctx context.Context) {
	defer c.close()
	defer c.r.unsubscribeAll(c)

	go c.writeLoop()

	go func() {
		select {
		case <-ctx.Done():
			c.close()
		case <-c.done:
		}
	}()

	br := bufio.NewReaderSize(c.nc, wire.CellSize*4)
	for {
		_ = c.nc.SetReadDeadline(time.Now().Add(c.r.opts.IdleTimeout))
		typ, payload, err := wire.Read(br)
		if err != nil {
			return
		}
		atomic.AddUint64(&c.r.cellsIn, 1)

		if !c.bucket.allow() {
			// Flooding. Drop the peer without explanation.
			return
		}
		if !c.handle(typ, payload) {
			return
		}
	}
}

func (c *conn) handle(typ wire.Type, payload []byte) bool {
	switch typ {
	case wire.TypeNoise:
		return true

	case wire.TypeHello:
		cell, err := wire.Marshal(wire.TypeHello, []byte{wire.Version})
		if err != nil {
			return false
		}
		c.send(cell)
		return true

	case wire.TypePing:
		cell, err := wire.Marshal(wire.TypePong, nil)
		if err != nil {
			return false
		}
		c.send(cell)
		return true

	case wire.TypeJoin:
		if len(payload) != wire.ChanIDLen {
			return false
		}
		var id [wire.ChanIDLen]byte
		copy(id[:], payload)
		if !c.r.subscribe(c, id) {
			cell, err := wire.Marshal(wire.TypeErr, []byte("chanlimit"))
			if err != nil {
				return false
			}
			c.send(cell)
		}
		return true

	case wire.TypePart:
		if len(payload) != wire.ChanIDLen {
			return false
		}
		var id [wire.ChanIDLen]byte
		copy(id[:], payload)
		c.r.unsubscribe(c, id)
		return true

	case wire.TypeData:
		id, _, _, err := wire.ParseData(payload)
		if err != nil {
			return false
		}
		c.r.mu.RLock()
		_, member := c.subs[id]
		c.r.mu.RUnlock()
		if !member {
			// Not subscribed: refuse to relay. Otherwise the relay is a
			// free write primitive into channels you never joined.
			return true
		}
		cell, err := wire.Marshal(wire.TypeData, payload)
		if err != nil {
			return false
		}
		c.r.fanout(id, cell)
		return true

	case wire.TypeBye:
		return false

	default:
		return true
	}
}

func (c *conn) writeLoop() {
	defer c.close()

	var noiseC <-chan time.Time
	var timer *time.Timer
	if c.r.opts.NoiseMean > 0 {
		timer = time.NewTimer(noise.Interval(c.r.opts.NoiseMean))
		defer timer.Stop()
		noiseC = timer.C
	}

	for {
		select {
		case <-c.done:
			return

		case cell := <-c.out:
			if !c.write(cell) {
				return
			}

		case <-noiseC:
			cell, err := wire.Noise()
			if err != nil || !c.write(cell) {
				return
			}
			atomic.AddUint64(&c.r.cellsOut, 1)
			timer.Reset(noise.Interval(c.r.opts.NoiseMean))
		}
	}
}

func (c *conn) write(cell []byte) bool {
	_ = c.nc.SetWriteDeadline(time.Now().Add(c.r.opts.WriteTimeout))
	_, err := c.nc.Write(cell)
	return err == nil
}

// bucket is a token bucket rate limiter.
type bucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newBucket(rate, burst float64) *bucket {
	return &bucket{rate: rate, burst: burst, tokens: burst, last: time.Now()}
}

func (b *bucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	b.last = now
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
