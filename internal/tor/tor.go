// Package tor provides the SOCKS5 dialer used by the client and the control
// port plumbing used by the relay to publish an ephemeral v3 onion service.
package tor

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// DefaultSOCKS is the address of a stock local tor daemon.
const DefaultSOCKS = "127.0.0.1:9050"

// DefaultControl is the address of a stock local tor control port.
const DefaultControl = "127.0.0.1:9051"

// DialFunc is the dialer signature used throughout ghostwire.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// ErrNotOnion is returned when a supposedly anonymous connection targets an
// address that is not a v3 onion service.
var ErrNotOnion = errors.New("tor: address is not a v3 onion service")

// SOCKS returns a dialer that routes through the tor SOCKS5 port.
//
// Every connection gets a fresh random SOCKS username/password pair, which
// makes tor isolate it onto its own circuit (stream isolation). Two ghostwire
// sessions from the same host therefore do not share an exit path and cannot
// be correlated by circuit reuse.
func SOCKS(socksAddr string, isolate bool) (DialFunc, error) {
	if socksAddr == "" {
		socksAddr = DefaultSOCKS
	}
	var auth *proxy.Auth
	if isolate {
		user, pass, err := randomAuth()
		if err != nil {
			return nil, err
		}
		auth = &proxy.Auth{User: user, Password: pass}
	}
	d, err := proxy.SOCKS5("tcp", socksAddr, auth, &net.Dialer{Timeout: 30 * time.Second})
	if err != nil {
		return nil, err
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("tor: SOCKS5 dialer does not support contexts")
	}
	return cd.DialContext, nil
}

// Direct returns a plain TCP dialer. It exposes your IP address to the relay
// and is only ever meant for local testing.
func Direct() DialFunc {
	d := &net.Dialer{Timeout: 15 * time.Second}
	return d.DialContext
}

// IsOnion reports whether addr is a v3 onion host:port.
func IsOnion(addr string) bool {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	host = strings.ToLower(host)
	if !strings.HasSuffix(host, ".onion") {
		return false
	}
	// v3 addresses are exactly 56 base32 chars plus ".onion".
	return len(strings.TrimSuffix(host, ".onion")) == 56
}
