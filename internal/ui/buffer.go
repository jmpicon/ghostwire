package ui

import "sync"

// maxScrollback is how many lines a buffer keeps. Everything lives in RAM and
// dies with the process: ghostwire never writes a log.
const maxScrollback = 2000

type buffer struct {
	mu     sync.Mutex
	name   string
	lines  []string
	unread int
}

func newBuffer(name string) *buffer {
	return &buffer{name: name, lines: make([]string, 0, 128)}
}

func (b *buffer) add(line string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lines = append(b.lines, line)
	if len(b.lines) > maxScrollback {
		copy(b.lines, b.lines[len(b.lines)-maxScrollback:])
		b.lines = b.lines[:maxScrollback]
	}
}

func (b *buffer) render() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, len(b.lines))
	copy(out, b.lines)
	return out
}

func (b *buffer) clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := range b.lines {
		b.lines[i] = ""
	}
	b.lines = b.lines[:0]
}
