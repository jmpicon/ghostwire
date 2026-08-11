// Package client implements the gw session: transport, cover traffic,
// per-channel crypto and the event stream the UI renders.
package client

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	gcrypto "github.com/jmpicon/ghostwire/internal/crypto"
	"github.com/jmpicon/ghostwire/internal/noise"
	"github.com/jmpicon/ghostwire/internal/tor"
	"github.com/jmpicon/ghostwire/internal/wire"
)

// Errors returned by the client API.
var (
	ErrNotJoined  = errors.New("client: not joined to that channel")
	ErrJoined     = errors.New("client: already joined")
	ErrTooLong    = errors.New("client: message too long")
	ErrNotRunning = errors.New("client: session is not connected")
	ErrBusy       = errors.New("client: send queue is full")
)

// FreshnessWindow bounds how far a message's timestamp may drift before it is
// rejected. It caps the value of replaying old ciphertext.
const FreshnessWindow = 15 * time.Minute

// Config configures a session.
type Config struct {
	// Addr is the relay, normally <56-char>.onion:1717.
	Addr string
	// Dial routes the connection. Use tor.SOCKS in anything but a lab.
	Dial tor.DialFunc
	// Identity signs outgoing messages.
	Identity *gcrypto.Identity
	// Nick is the cosmetic display name.
	Nick string
	// NoiseMean is the mean cover-traffic interval. Zero disables cover
	// traffic, which is a downgrade you should have a reason for.
	NoiseMean time.Duration
	// SendJitter randomises outbound timing to break keystroke correlation.
	SendJitter time.Duration
	// Reconnect keeps the session alive across circuit failures.
	Reconnect bool
}

func (c *Config) normalize() {
	if c.NoiseMean < 0 {
		c.NoiseMean = 0
	}
	if c.SendJitter < 0 {
		c.SendJitter = 0
	}
	if strings.TrimSpace(c.Nick) == "" {
		c.Nick = "anon"
	}
	if len(c.Nick) > 32 {
		c.Nick = c.Nick[:32]
	}
}

// EventKind classifies a UI event.
type EventKind int

// Event kinds emitted on the client's event channel.
const (
	EvMessage EventKind = iota
	EvPresence
	EvSystem
	EvError
	EvConnected
	EvDisconnected
)

// Event is what the UI consumes.
type Event struct {
	Kind    EventKind
	Channel string
	Msg     *gcrypto.Message
	Text    string
	Self    bool
	At      time.Time
}

// Member is a fingerprint the client has actually heard from.
type Member struct {
	Fingerprint string
	Nick        string
	LastSeen    time.Time
	Self        bool
}

type joined struct {
	ch    *gcrypto.Channel
	reasm *wire.Reassembler

	mu      sync.RWMutex
	members map[string]*Member
}

// Client is a live ghostwire session.
type Client struct {
	cfg Config

	events chan Event
	guard  *gcrypto.ReplayGuard

	mu     sync.RWMutex
	chans  map[string]*joined
	byID   map[[wire.ChanIDLen]byte]*joined
	conn   net.Conn
	outbox chan []byte

	// sendq carries whole messages, already sealed and split into cells.
	// Everything goes out through this one queue so that send jitter delays
	// the stream rather than each message independently: jittering per
	// message reorders any burst, which for a multi-line incident report is
	// worse than useless.
	sendq chan [][]byte

	nickMu sync.RWMutex
	nick   string

	closeOnce sync.Once
	done      chan struct{}
}

// New builds a client. Call Run to connect.
func New(cfg Config) (*Client, error) {
	cfg.normalize()
	if cfg.Identity == nil {
		return nil, errors.New("client: identity is required")
	}
	if cfg.Dial == nil {
		return nil, errors.New("client: dialer is required")
	}
	if strings.TrimSpace(cfg.Addr) == "" {
		return nil, errors.New("client: relay address is required")
	}
	c := &Client{
		cfg:    cfg,
		events: make(chan Event, 256),
		guard:  gcrypto.NewReplayGuard(FreshnessWindow),
		chans:  make(map[string]*joined),
		byID:   make(map[[wire.ChanIDLen]byte]*joined),
		outbox: make(chan []byte, 512),
		sendq:  make(chan [][]byte, 128),
		nick:   cfg.Nick,
		done:   make(chan struct{}),
	}
	go c.sendLoop()
	return c, nil
}

// sendLoop serialises outbound messages. One goroutine, one queue: jitter is
// applied between messages, never in parallel across them, so the order a
// caller wrote is the order the channel sees.
func (c *Client) sendLoop() {
	for {
		select {
		case <-c.done:
			return
		case cells := <-c.sendq:
			if d := noise.Jitter(c.cfg.SendJitter); d > 0 {
				select {
				case <-time.After(d):
				case <-c.done:
					return
				}
			}
			for _, payload := range cells {
				cell, err := wire.Marshal(wire.TypeData, payload)
				if err != nil {
					break
				}
				c.enqueue(cell)
			}
		}
	}
}

// Events is the stream the UI ranges over.
func (c *Client) Events() <-chan Event { return c.events }

// Fingerprint of this session's identity.
func (c *Client) Fingerprint() string { return c.cfg.Identity.Fingerprint() }

// Nick returns the current display name.
func (c *Client) Nick() string {
	c.nickMu.RLock()
	defer c.nickMu.RUnlock()
	return c.nick
}

// SetNick changes the display name and announces it on every joined channel.
func (c *Client) SetNick(n string) {
	n = strings.TrimSpace(n)
	if n == "" {
		return
	}
	if len(n) > 32 {
		n = n[:32]
	}
	c.nickMu.Lock()
	old := c.nick
	c.nick = n
	c.nickMu.Unlock()

	for _, name := range c.Channels() {
		_ = c.sendPresence(name, "nick "+old)
	}
}

// Run drives the session until ctx is cancelled. With Reconnect set it retries
// forever with exponential backoff and randomised delay.
func (c *Client) Run(ctx context.Context) error {
	defer close(c.events)
	defer c.close()

	backoff := 2 * time.Second
	for {
		err := c.session(ctx)
		if ctx.Err() != nil {
			return nil
		}
		c.emit(Event{Kind: EvDisconnected, Text: reason(err), At: time.Now()})
		if !c.cfg.Reconnect {
			return err
		}
		delay := backoff + noise.Jitter(backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
		if backoff < 60*time.Second {
			backoff *= 2
		}
	}
}

func reason(err error) string {
	if err == nil {
		return "connection closed"
	}
	return err.Error()
}

func (c *Client) session(ctx context.Context) error {
	dialCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	conn, err := c.cfg.Dial(dialCtx, "tcp", c.cfg.Addr)
	cancel()
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()

	sctx, stop := context.WithCancel(ctx)
	defer stop()
	defer conn.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); c.writeLoop(sctx, conn) }()
	defer wg.Wait()

	if hello, err := wire.Marshal(wire.TypeHello, []byte{wire.Version}); err == nil {
		c.enqueue(hello)
	}

	// Re-subscribe every channel: after a circuit change the relay has no
	// memory of us at all.
	for _, id := range c.channelIDs() {
		if cell, err := wire.Marshal(wire.TypeJoin, id[:]); err == nil {
			c.enqueue(cell)
		}
	}
	c.emit(Event{Kind: EvConnected, Text: c.cfg.Addr, At: time.Now()})
	for _, name := range c.Channels() {
		_ = c.sendPresence(name, "join")
	}

	err = c.readLoop(conn)
	stop()
	return err
}

func (c *Client) writeLoop(ctx context.Context, conn net.Conn) {
	var noiseC <-chan time.Time
	var timer *time.Timer
	if c.cfg.NoiseMean > 0 {
		timer = time.NewTimer(noise.Interval(c.cfg.NoiseMean))
		defer timer.Stop()
		noiseC = timer.C
	}
	ping := time.NewTicker(90 * time.Second)
	defer ping.Stop()

	write := func(cell []byte) bool {
		_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		_, err := conn.Write(cell)
		return err == nil
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case cell := <-c.outbox:
			if !write(cell) {
				return
			}
		case <-noiseC:
			cell, err := wire.Noise()
			if err != nil || !write(cell) {
				return
			}
			timer.Reset(noise.Interval(c.cfg.NoiseMean))
		case <-ping.C:
			cell, err := wire.Marshal(wire.TypePing, nil)
			if err != nil || !write(cell) {
				return
			}
		}
	}
}

func (c *Client) readLoop(conn net.Conn) error {
	br := bufio.NewReaderSize(conn, wire.CellSize*8)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Minute))
		typ, payload, err := wire.Read(br)
		if err != nil {
			return err
		}
		switch typ {
		case wire.TypeData:
			c.onData(payload)
		case wire.TypeErr:
			c.emit(Event{Kind: EvError, Text: "relay: " + string(payload), At: time.Now()})
		default:
			// NOISE, HELLO, PONG: nothing to do, by design.
		}
	}
}

func (c *Client) onData(payload []byte) {
	id, more, chunk, err := wire.ParseData(payload)
	if err != nil {
		return
	}
	c.mu.RLock()
	j := c.byID[id]
	c.mu.RUnlock()
	if j == nil {
		return
	}

	blob, err := j.reasm.Push(id, more, chunk)
	if err != nil || blob == nil {
		return
	}

	now := time.Now()
	if c.guard.Seen(gcrypto.ReplayID(blob), now) {
		return
	}
	pt, err := j.ch.Open(blob, now)
	if err != nil {
		// Someone in the channel-id namespace we cannot decrypt. Could be
		// an unrelated channel colliding, could be an active probe. Either
		// way it is not our business and never reaches the UI.
		return
	}
	msg, err := gcrypto.ParseMessage(pt, now, FreshnessWindow)
	if err != nil {
		return
	}

	self := msg.Fingerprint() == c.Fingerprint()
	j.touch(msg, self, now)

	switch msg.Kind {
	case gcrypto.KindPresence:
		c.emit(Event{Kind: EvPresence, Channel: j.ch.Name, Msg: msg, Self: self, At: now})
	default:
		c.emit(Event{Kind: EvMessage, Channel: j.ch.Name, Msg: msg, Self: self, At: now})
	}
}

func (j *joined) touch(msg *gcrypto.Message, self bool, now time.Time) {
	fp := msg.Fingerprint()
	j.mu.Lock()
	defer j.mu.Unlock()

	if msg.Kind == gcrypto.KindPresence && msg.Body == "part" {
		delete(j.members, fp)
		return
	}
	m := j.members[fp]
	if m == nil {
		m = &Member{Fingerprint: fp, Self: self}
		j.members[fp] = m
	}
	m.Nick = msg.Nick
	m.LastSeen = now
}

// Join derives the channel from name+passphrase and subscribes to it.
func (c *Client) Join(name, passphrase string) error {
	ch := gcrypto.DeriveChannel(name, passphrase)

	c.mu.Lock()
	if _, dup := c.chans[ch.Name]; dup {
		c.mu.Unlock()
		ch.Zeroize()
		return ErrJoined
	}
	j := &joined{ch: ch, reasm: wire.NewReassembler(256 << 10), members: map[string]*Member{}}
	c.chans[ch.Name] = j
	c.byID[ch.ID()] = j
	c.mu.Unlock()

	id := ch.ID()
	cell, err := wire.Marshal(wire.TypeJoin, id[:])
	if err != nil {
		return err
	}
	c.enqueue(cell)
	c.emit(Event{Kind: EvSystem, Channel: ch.Name,
		Text: fmt.Sprintf("joined %s  (relay tag %s…)", ch.Name, hexShort(id[:])), At: time.Now()})
	return c.sendPresence(ch.Name, "join")
}

// Part announces a departure, unsubscribes and destroys the channel key.
func (c *Client) Part(name string) error {
	n := gcrypto.NormalizeChannel(name)

	c.mu.RLock()
	j := c.chans[n]
	c.mu.RUnlock()
	if j == nil {
		return ErrNotJoined
	}

	_ = c.sendPresence(n, "part")

	id := j.ch.ID()
	if cell, err := wire.Marshal(wire.TypePart, id[:]); err == nil {
		c.enqueue(cell)
	}

	c.mu.Lock()
	delete(c.chans, n)
	delete(c.byID, id)
	c.mu.Unlock()

	j.reasm.Forget(id)
	j.ch.Zeroize()
	c.emit(Event{Kind: EvSystem, Channel: n, Text: "left " + n + " (key destroyed)", At: time.Now()})
	return nil
}

// Say sends a line to a joined channel.
func (c *Client) Say(name, text string) error {
	return c.sendKind(name, gcrypto.KindMsg, text)
}

// Action sends a /me line.
func (c *Client) Action(name, text string) error {
	return c.sendKind(name, gcrypto.KindAction, text)
}

func (c *Client) sendPresence(name, body string) error {
	return c.sendKind(name, gcrypto.KindPresence, body)
}

func (c *Client) sendKind(name string, kind gcrypto.Kind, body string) error {
	n := gcrypto.NormalizeChannel(name)
	c.mu.RLock()
	j := c.chans[n]
	c.mu.RUnlock()
	if j == nil {
		return ErrNotJoined
	}
	if len(body) > 8<<10 {
		return ErrTooLong
	}

	now := time.Now()
	msg := &gcrypto.Message{Kind: kind, Nick: c.Nick(), Sent: now, Body: body}
	pt, err := msg.Marshal(c.cfg.Identity)
	if err != nil {
		return err
	}
	sealed, err := j.ch.Seal(pt, now)
	if err != nil {
		return err
	}
	cells, err := wire.SplitData(j.ch.ID(), sealed)
	if err != nil {
		return err
	}

	select {
	case c.sendq <- cells:
		return nil
	case <-c.done:
		return ErrNotRunning
	default:
		return ErrBusy
	}
}

// Channels lists joined channel names, sorted.
func (c *Client) Channels() []string {
	c.mu.RLock()
	out := make([]string, 0, len(c.chans))
	for n := range c.chans {
		out = append(out, n)
	}
	c.mu.RUnlock()
	sort.Strings(out)
	return out
}

// Members returns everyone the client has actually heard from in a channel.
// Silence is invisible on purpose: there is no presence protocol to query.
func (c *Client) Members(name string) []Member {
	c.mu.RLock()
	j := c.chans[gcrypto.NormalizeChannel(name)]
	c.mu.RUnlock()
	if j == nil {
		return nil
	}
	j.mu.RLock()
	out := make([]Member, 0, len(j.members))
	for _, m := range j.members {
		out = append(out, *m)
	}
	j.mu.RUnlock()
	sort.Slice(out, func(i, k int) bool { return out[i].Nick < out[k].Nick })
	return out
}

func (c *Client) channelIDs() [][wire.ChanIDLen]byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([][wire.ChanIDLen]byte, 0, len(c.byID))
	for id := range c.byID {
		out = append(out, id)
	}
	return out
}

func (c *Client) enqueue(cell []byte) {
	select {
	case c.outbox <- cell:
	case <-c.done:
	default:
	}
}

func (c *Client) emit(e Event) {
	select {
	case c.events <- e:
	case <-c.done:
	default:
	}
}

// Drain blocks until every queued cell has been handed to the transport, or
// until timeout elapses. Callers that exit immediately after Say would
// otherwise drop the tail of their own traffic on the floor.
func (c *Client) Drain(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if len(c.outbox) == 0 {
			// Give the writer goroutine a moment to flush the last cell.
			time.Sleep(200 * time.Millisecond)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Panic destroys every key this process holds and tears the session down. It
// is the /panic command: assume the machine is about to stop being yours.
func (c *Client) Panic() {
	c.mu.Lock()
	for _, j := range c.chans {
		j.ch.Zeroize()
	}
	c.chans = make(map[string]*joined)
	c.byID = make(map[[wire.ChanIDLen]byte]*joined)
	conn := c.conn
	c.mu.Unlock()

	c.cfg.Identity.Zeroize()
	if conn != nil {
		_ = conn.Close()
	}
	c.close()
}

// Close shuts the session down cleanly.
func (c *Client) Close() {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()
	if conn != nil {
		if cell, err := wire.Marshal(wire.TypeBye, nil); err == nil {
			_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_, _ = conn.Write(cell)
		}
		_ = conn.Close()
	}
	c.close()
}

func (c *Client) close() { c.closeOnce.Do(func() { close(c.done) }) }

func hexShort(b []byte) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, 0, 12)
	for _, x := range b[:6] {
		out = append(out, hexd[x>>4], hexd[x&0x0f])
	}
	return string(out)
}
