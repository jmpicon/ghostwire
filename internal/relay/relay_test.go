package relay_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/jmpicon/ghostwire/internal/client"
	gcrypto "github.com/jmpicon/ghostwire/internal/crypto"
	"github.com/jmpicon/ghostwire/internal/relay"
	"github.com/jmpicon/ghostwire/internal/tor"
)

// startRelay spins a relay on loopback with cover traffic disabled so the
// tests are deterministic.
func startRelay(t *testing.T) (addr string, stop func(), r *relay.Relay) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	opts := relay.DefaultOptions()
	opts.NoiseMean = 0
	r = relay.New(opts)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = r.Serve(ctx, ln) }()

	return ln.Addr().String(), func() {
		cancel()
		<-done
	}, r
}

func startClient(t *testing.T, addr, nick string) (*client.Client, <-chan client.Event, func()) {
	t.Helper()

	id, err := gcrypto.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	cli, err := client.New(client.Config{
		Addr:      addr,
		Dial:      tor.Direct(),
		Identity:  id,
		Nick:      nick,
		NoiseMean: 0,
		// Non-zero on purpose: jitter is the code path that used to reorder
		// bursts, so every test exercises it.
		SendJitter: 150 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = cli.Run(ctx) }()

	// Wait for the link to come up.
	ev := cli.Events()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case e := <-ev:
			if e.Kind == client.EvConnected {
				return cli, ev, func() { cancel(); cli.Close() }
			}
		case <-deadline:
			t.Fatalf("%s never connected", nick)
		}
	}
}

func waitMessage(t *testing.T, ev <-chan client.Event, within time.Duration) *client.Event {
	t.Helper()
	deadline := time.After(within)
	for {
		select {
		case e := <-ev:
			if e.Kind == client.EvMessage {
				return &e
			}
		case <-deadline:
			return nil
		}
	}
}

func TestTwoPeersExchangeMessages(t *testing.T) {
	addr, stop, _ := startRelay(t)
	defer stop()

	alice, aliceEv, ca := startClient(t, addr, "alice")
	defer ca()
	bob, bobEv, cb := startClient(t, addr, "bob")
	defer cb()

	const pass = "a passphrase nobody guessed"
	if err := alice.Join("#ops", pass); err != nil {
		t.Fatal(err)
	}
	if err := bob.Join("#ops", pass); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)

	if err := alice.Say("#ops", "the package is in the usual place"); err != nil {
		t.Fatal(err)
	}

	got := waitMessage(t, bobEv, 5*time.Second)
	if got == nil {
		t.Fatal("bob never received alice's message")
	}
	if got.Msg.Body != "the package is in the usual place" {
		t.Fatalf("body = %q", got.Msg.Body)
	}
	if got.Msg.Nick != "alice" {
		t.Fatalf("nick = %q", got.Msg.Nick)
	}
	if got.Msg.Fingerprint() != alice.Fingerprint() {
		t.Fatal("sender fingerprint does not match alice")
	}

	// Alice gets her own message echoed back: that is the delivery receipt.
	self := waitMessage(t, aliceEv, 5*time.Second)
	if self == nil || !self.Self {
		t.Fatal("alice did not receive the echo of her own message")
	}
}

func TestWrongPassphraseSeesNothing(t *testing.T) {
	addr, stop, _ := startRelay(t)
	defer stop()

	alice, _, ca := startClient(t, addr, "alice")
	defer ca()
	mallory, malloryEv, cm := startClient(t, addr, "mallory")
	defer cm()

	if err := alice.Join("#ops", "right"); err != nil {
		t.Fatal(err)
	}
	// Same channel name, wrong passphrase: a different channel id entirely,
	// so mallory is not even subscribed to the same relay bucket.
	if err := mallory.Join("#ops", "wrong"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)

	if err := alice.Say("#ops", "classified"); err != nil {
		t.Fatal(err)
	}
	if got := waitMessage(t, malloryEv, 2*time.Second); got != nil {
		t.Fatalf("mallory read a message she has no key for: %q", got.Msg.Body)
	}
}

func TestRelayNeverLearnsChannelNames(t *testing.T) {
	addr, stop, r := startRelay(t)
	defer stop()

	alice, _, ca := startClient(t, addr, "alice")
	defer ca()
	if err := alice.Join("#a-very-distinctive-name", "pass"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)

	// The relay's entire view of the world is a count.
	s := r.Stats()
	if s.Channels != 1 {
		t.Fatalf("relay tracks %d channels, want 1", s.Channels)
	}
	if s.Conns != 1 {
		t.Fatalf("relay tracks %d conns, want 1", s.Conns)
	}
}

func TestLargeMessageSurvivesFragmentation(t *testing.T) {
	addr, stop, _ := startRelay(t)
	defer stop()

	alice, _, ca := startClient(t, addr, "alice")
	defer ca()
	bob, bobEv, cb := startClient(t, addr, "bob")
	defer cb()

	const pass = "pass"
	if err := alice.Join("#big", pass); err != nil {
		t.Fatal(err)
	}
	if err := bob.Join("#big", pass); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)

	body := make([]byte, 4000)
	for i := range body {
		body[i] = byte('a' + i%26)
	}
	if err := alice.Say("#big", string(body)); err != nil {
		t.Fatal(err)
	}

	got := waitMessage(t, bobEv, 5*time.Second)
	if got == nil {
		t.Fatal("fragmented message never arrived")
	}
	if got.Msg.Body != string(body) {
		t.Fatalf("fragmented message corrupted: got %d bytes, want %d", len(got.Msg.Body), len(body))
	}
}

func TestPartStopsDelivery(t *testing.T) {
	addr, stop, _ := startRelay(t)
	defer stop()

	alice, _, ca := startClient(t, addr, "alice")
	defer ca()
	bob, bobEv, cb := startClient(t, addr, "bob")
	defer cb()

	const pass = "pass"
	_ = alice.Join("#ops", pass)
	_ = bob.Join("#ops", pass)
	time.Sleep(300 * time.Millisecond)

	if err := bob.Part("#ops"); err != nil {
		t.Fatal(err)
	}
	// Drain whatever is already queued, including bob's own part notice.
	time.Sleep(300 * time.Millisecond)
	for {
		select {
		case <-bobEv:
			continue
		default:
		}
		break
	}

	if err := alice.Say("#ops", "after bob left"); err != nil {
		t.Fatal(err)
	}
	if got := waitMessage(t, bobEv, 2*time.Second); got != nil {
		t.Fatalf("bob still received traffic after parting: %q", got.Msg.Body)
	}
}

// TestBurstPreservesOrder guards the property an alerting channel depends on:
// a script that emits a multi-line report must have those lines arrive in the
// order it wrote them. Send jitter used to be applied per message in its own
// goroutine, which shuffled any burst.
func TestBurstPreservesOrder(t *testing.T) {
	addr, stop, _ := startRelay(t)
	defer stop()

	alice, _, ca := startClient(t, addr, "alice")
	defer ca()
	bob, bobEv, cb := startClient(t, addr, "bob")
	defer cb()

	const pass = "pass"
	_ = alice.Join("#burst", pass)
	_ = bob.Join("#burst", pass)
	time.Sleep(300 * time.Millisecond)

	const n = 12
	for i := 0; i < n; i++ {
		if err := alice.Say("#burst", fmt.Sprintf("line-%02d", i)); err != nil {
			t.Fatalf("say %d: %v", i, err)
		}
	}

	for i := 0; i < n; i++ {
		got := waitMessage(t, bobEv, 10*time.Second)
		if got == nil {
			t.Fatalf("only %d of %d lines arrived", i, n)
		}
		if want := fmt.Sprintf("line-%02d", i); got.Msg.Body != want {
			t.Fatalf("burst reordered: position %d is %q, want %q", i, got.Msg.Body, want)
		}
	}
}
