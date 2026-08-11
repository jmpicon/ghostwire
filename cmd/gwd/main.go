// Command gwd is the ghostwire relay: a blind, stateless, log-free rendezvous
// point that publishes itself as a v3 onion service.
//
// It stores nothing on disk, keeps no per-connection records and cannot read
// a single byte of the traffic it forwards. Running one is cheap; running
// several and telling nobody which you use is cheaper still.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jmpicon/ghostwire/internal/relay"
	"github.com/jmpicon/ghostwire/internal/tor"
)

var version = "dev"

func main() {
	var (
		listen      = flag.String("listen", "127.0.0.1:1717", "local address to bind")
		onion       = flag.Bool("onion", false, "publish an ephemeral v3 onion service via the tor control port")
		ctrlAddr    = flag.String("tor-control", tor.DefaultControl, "tor control port")
		ctrlPass    = flag.String("tor-password", "", "tor control password (HashedControlPassword)")
		ctrlCookie  = flag.String("tor-cookie", "", "path to tor's control_auth_cookie")
		onionKey    = flag.String("onion-key", "", "file holding the onion private key (created if absent; keeps a stable address)")
		virtPort    = flag.Int("onion-port", 1717, "virtual port advertised by the onion service")
		maxConns    = flag.Int("max-conns", 512, "maximum concurrent connections")
		maxChans    = flag.Int("max-chans", 16, "maximum channels per connection")
		rate        = flag.Float64("rate", 64, "cells per second accepted from one connection")
		idle        = flag.Duration("idle", 5*time.Minute, "drop a connection after this much silence")
		noiseMean   = flag.Duration("noise", 20*time.Second, "mean interval of relay->client cover traffic (0 disables)")
		statsEvery  = flag.Duration("stats", 0, "print aggregate counters at this interval (0 = never)")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		fmt.Printf("gwd %s\n", version)
		return
	}

	opts := relay.DefaultOptions()
	opts.MaxConns = *maxConns
	opts.MaxChansPerConn = *maxChans
	opts.CellsPerSecond = *rate
	opts.CellBurst = *rate * 4
	opts.IdleTimeout = *idle
	opts.NoiseMean = *noiseMean

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fatal("listen %s: %v", *listen, err)
	}
	defer ln.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stderr, "gwd %s listening on %s\n", version, ln.Addr())

	if *onion {
		ctl, addr, err := publish(*ctrlAddr, *ctrlPass, *ctrlCookie, *onionKey, *virtPort, ln.Addr().String())
		if err != nil {
			fatal("onion: %v", err)
		}
		defer ctl.Close()
		fmt.Fprintf(os.Stderr, "\n  onion service live:\n\n    %s\n\n", addr)
		fmt.Fprintf(os.Stderr, "  share it out of band. anyone with the address still needs\n")
		fmt.Fprintf(os.Stderr, "  a channel name and passphrase to read a single byte.\n\n")
		fmt.Fprintf(os.Stderr, "    gw -relay %s -join '#room'\n\n", addr)
	} else {
		fmt.Fprintf(os.Stderr, "note: this process is not publishing an onion service.\n")
		fmt.Fprintf(os.Stderr, "      that is correct if an external tor publishes one for you\n")
		fmt.Fprintf(os.Stderr, "      (see deploy/torrc). otherwise clients reach this relay\n")
		fmt.Fprintf(os.Stderr, "      over clearnet and it sees their IP addresses — use -onion.\n")
	}

	r := relay.New(opts)
	if *statsEvery > 0 {
		go reportStats(ctx, r, *statsEvery)
	}

	if err := r.Serve(ctx, ln); err != nil {
		fatal("serve: %v", err)
	}
	fmt.Fprintln(os.Stderr, "gwd stopped. nothing was written to disk.")
}

func publish(ctrlAddr, pass, cookie, keyPath string, virtPort int, target string) (*tor.Controller, string, error) {
	ctl, err := tor.DialControl(ctrlAddr)
	if err != nil {
		return nil, "", err
	}
	if err := ctl.Authenticate(pass, cookie); err != nil {
		ctl.Close()
		return nil, "", fmt.Errorf("authenticate: %w", err)
	}

	var existing string
	if keyPath != "" {
		if raw, err := os.ReadFile(keyPath); err == nil {
			existing = strings.TrimSpace(string(raw))
		}
	}

	serviceID, key, err := ctl.AddOnion(existing, virtPort, target)
	if err != nil {
		ctl.Close()
		return nil, "", err
	}
	if keyPath != "" && existing == "" && key != "" {
		if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err == nil {
			if err := os.WriteFile(keyPath, []byte(key+"\n"), 0o600); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not persist onion key: %v\n", err)
			}
		}
	}
	return ctl, net.JoinHostPort(serviceID+".onion", strconv.Itoa(virtPort)), nil
}

func reportStats(ctx context.Context, r *relay.Relay, every time.Duration) {
	tk := time.NewTicker(every)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			s := r.Stats()
			// Aggregates only. There is deliberately no way to ask this
			// process who is connected or which channels exist.
			fmt.Fprintf(os.Stderr, "conns=%d chans=%d in=%d out=%d dropped=%d\n",
				s.Conns, s.Channels, s.CellsIn, s.CellsOut, s.Dropped)
		}
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gwd: "+format+"\n", args...)
	os.Exit(1)
}

func usage() {
	fmt.Fprint(os.Stderr, `gwd — the ghostwire relay

  A relay that cannot betray you because it never learns anything.
  No accounts, no disk state, no per-connection logs, no plaintext.

usage:
  gwd -onion                            publish an ephemeral onion and serve
  gwd -onion -onion-key ~/.gw/onion.key keep a stable .onion across restarts
  gwd -listen 0.0.0.0:1717              serve behind an external tor/torrc

flags:
`)
	flag.PrintDefaults()
}
