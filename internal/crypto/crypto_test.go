package crypto

import (
	"bytes"
	"testing"
	"time"
)

func TestChannelDerivationIsDeterministicAndNormalised(t *testing.T) {
	a := DeriveChannel("#ops", "correct horse battery staple")
	b := DeriveChannel("  OPS ", "correct horse battery staple")
	if a.ID() != b.ID() {
		t.Fatal("channel name normalisation failed: #ops and OPS derived different ids")
	}
	if a.Name != "#ops" {
		t.Fatalf("normalised name = %q", a.Name)
	}
}

func TestWrongPassphraseGivesDifferentChannel(t *testing.T) {
	a := DeriveChannel("#ops", "one")
	b := DeriveChannel("#ops", "two")
	if a.ID() == b.ID() {
		t.Fatal("different passphrases produced the same relay-visible channel id")
	}
}

func TestChannelIDLeaksNothingAboutTheName(t *testing.T) {
	c := DeriveChannel("#ops", "pass")
	id := c.ID()
	if bytes.Contains(id[:], []byte("ops")) {
		t.Fatal("channel id contains the channel name")
	}
	if id == c.master {
		t.Fatal("channel id equals the master key: the relay would hold the key")
	}
}

func TestSealOpenRoundtrip(t *testing.T) {
	c := DeriveChannel("#ops", "pass")
	now := time.Now()
	pt := []byte("meet at the usual place")

	ct, err := c.Seal(pt, now)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, pt) {
		t.Fatal("plaintext is visible in the ciphertext")
	}
	got, err := c.Open(ct, now)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatal("roundtrip mismatch")
	}
}

func TestOpenRejectsWrongChannel(t *testing.T) {
	a := DeriveChannel("#ops", "pass")
	b := DeriveChannel("#ops", "other")
	ct, err := a.Seal([]byte("secret"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Open(ct, time.Now()); err != ErrOpen {
		t.Fatalf("wrong passphrase opened the payload: %v", err)
	}
}

func TestOpenRejectsTamperedCiphertext(t *testing.T) {
	c := DeriveChannel("#ops", "pass")
	ct, err := c.Seal([]byte("secret"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ct[len(ct)-1] ^= 0x01
	if _, err := c.Open(ct, time.Now()); err != ErrOpen {
		t.Fatal("tampered ciphertext authenticated")
	}
}

func TestEpochSkewTolerated(t *testing.T) {
	c := DeriveChannel("#ops", "pass")
	now := time.Now()
	ct, err := c.Seal([]byte("hello"), now)
	if err != nil {
		t.Fatal(err)
	}
	// A peer one epoch ahead and one epoch behind must both still read it.
	for _, delta := range []time.Duration{EpochSeconds * time.Second, -EpochSeconds * time.Second} {
		if _, err := c.Open(ct, now.Add(delta)); err != nil {
			t.Fatalf("skew %v: %v", delta, err)
		}
	}
	// Two epochs out must not.
	if _, err := c.Open(ct, now.Add(3*EpochSeconds*time.Second)); err == nil {
		t.Fatal("a ciphertext three epochs old still opened; key rotation is not happening")
	}
}

func TestMessageSignAndVerify(t *testing.T) {
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	m := &Message{Kind: KindMsg, Nick: "ghost", Sent: now, Body: "hello · unicode · [tags]"}
	raw, err := m.Marshal(id)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseMessage(raw, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if got.Body != m.Body || got.Nick != m.Nick || got.Kind != m.Kind {
		t.Fatal("message roundtrip mismatch")
	}
	if got.Fingerprint() != id.Fingerprint() {
		t.Fatal("fingerprint mismatch")
	}
}

func TestForgedMessageRejected(t *testing.T) {
	mallory, _ := NewIdentity()
	now := time.Now()
	m := &Message{Kind: KindMsg, Nick: "admin", Sent: now, Body: "trust me"}
	raw, err := m.Marshal(mallory)
	if err != nil {
		t.Fatal(err)
	}
	// Swap in somebody else's public key: a channel member holds the
	// symmetric key and could try exactly this.
	victim, _ := NewIdentity()
	copy(raw[2:2+32], victim.Public())
	if _, err := ParseMessage(raw, now, time.Minute); err != ErrBadSignature {
		t.Fatalf("forged sender accepted: %v", err)
	}
}

func TestStaleMessageRejected(t *testing.T) {
	id, _ := NewIdentity()
	old := time.Now().Add(-2 * time.Hour)
	raw, err := (&Message{Kind: KindMsg, Nick: "x", Sent: old, Body: "replay"}).Marshal(id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseMessage(raw, time.Now(), 15*time.Minute); err != ErrStale {
		t.Fatalf("stale message accepted: %v", err)
	}
}

func TestTimestampIsCoarse(t *testing.T) {
	id, _ := NewIdentity()
	now := time.Date(2026, 8, 11, 12, 34, 57, 123456789, time.UTC)
	raw, _ := (&Message{Kind: KindMsg, Nick: "x", Sent: now, Body: "y"}).Marshal(id)
	got, err := ParseMessage(raw, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got.Sent.Unix()%int64(TimeGranularity/time.Second) != 0 {
		t.Fatalf("timestamp %v was not quantised to %v", got.Sent, TimeGranularity)
	}
}

func TestReplayGuard(t *testing.T) {
	g := NewReplayGuard(time.Minute)
	id := ReplayID([]byte("ciphertext"))
	now := time.Now()
	if g.Seen(id, now) {
		t.Fatal("first sighting reported as a replay")
	}
	if !g.Seen(id, now) {
		t.Fatal("replay not detected")
	}
}

func TestZeroizeWipesKeyMaterial(t *testing.T) {
	c := DeriveChannel("#ops", "pass")
	c.Zeroize()
	if c.master != [KeyLen]byte{} {
		t.Fatal("master key survived Zeroize")
	}
}
