package wire

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestCellIsAlwaysCellSize(t *testing.T) {
	for _, n := range []int{0, 1, 100, MaxPayload} {
		payload := make([]byte, n)
		if _, err := rand.Read(payload); err != nil {
			t.Fatal(err)
		}
		cell, err := Marshal(TypeData, payload)
		if err != nil {
			t.Fatalf("marshal %d: %v", n, err)
		}
		if len(cell) != CellSize {
			t.Fatalf("payload %d produced a %d-byte cell; every cell must be %d", n, len(cell), CellSize)
		}
		typ, got, err := Parse(cell)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if typ != TypeData || !bytes.Equal(got, payload) {
			t.Fatalf("roundtrip mismatch for payload of %d bytes", n)
		}
	}
}

func TestPaddingIsRandom(t *testing.T) {
	a, err := Marshal(TypeNoise, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Marshal(TypeNoise, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two noise cells are identical: padding is not random")
	}
	if bytes.Equal(a[HeaderLen:], make([]byte, MaxPayload)) {
		t.Fatal("padding is zeroed, not random")
	}
}

func TestOversizeRejected(t *testing.T) {
	if _, err := Marshal(TypeData, make([]byte, MaxPayload+1)); err != ErrOversize {
		t.Fatalf("want ErrOversize, got %v", err)
	}
}

func TestBadVersionRejected(t *testing.T) {
	cell, err := Marshal(TypeData, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	cell[0] = 0xff
	if _, _, err := Parse(cell); err != ErrBadVersion {
		t.Fatalf("want ErrBadVersion, got %v", err)
	}
}

func TestFragmentAndReassemble(t *testing.T) {
	var id [ChanIDLen]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	blob := make([]byte, MaxChunk*3+17)
	if _, err := rand.Read(blob); err != nil {
		t.Fatal(err)
	}

	payloads, err := SplitData(id, blob)
	if err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 4 {
		t.Fatalf("want 4 fragments, got %d", len(payloads))
	}

	r := NewReassembler(1 << 20)
	var out []byte
	for i, p := range payloads {
		gotID, more, chunk, err := ParseData(p)
		if err != nil {
			t.Fatal(err)
		}
		if gotID != id {
			t.Fatal("channel id mangled by fragmentation")
		}
		if want := i < len(payloads)-1; more != want {
			t.Fatalf("fragment %d: more=%v want %v", i, more, want)
		}
		blobOut, err := r.Push(gotID, more, chunk)
		if err != nil {
			t.Fatal(err)
		}
		if blobOut != nil {
			out = blobOut
		}
	}
	if !bytes.Equal(out, blob) {
		t.Fatal("reassembled blob differs from the original")
	}
}

func TestReassemblyIsBounded(t *testing.T) {
	var id [ChanIDLen]byte
	r := NewReassembler(1024)
	chunk := make([]byte, 512)
	for i := 0; i < 10; i++ {
		if _, err := r.Push(id, true, chunk); err == ErrReassemblyLimit {
			return
		}
	}
	t.Fatal("reassembler accepted unbounded fragments")
}
