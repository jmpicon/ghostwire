package tor

import (
	"bufio"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// Controller speaks the tor control protocol.
//
// gwd uses it to create an ephemeral v3 onion service at runtime, so a relay
// needs no torrc edits, no HiddenServiceDir on disk and no root. The service
// is bound to the lifetime of this control connection: when gwd exits, the
// onion descriptor stops being published.
type Controller struct {
	c  net.Conn
	br *bufio.Reader
}

// DialControl connects to a tor control port.
func DialControl(addr string) (*Controller, error) {
	if addr == "" {
		addr = DefaultControl
	}
	c, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("tor: control port %s: %w", addr, err)
	}
	return &Controller{c: c, br: bufio.NewReader(c)}, nil
}

// Close drops the control connection (and with it any ephemeral onion).
func (t *Controller) Close() error { return t.c.Close() }

// Authenticate performs control-port auth. It prefers the cookie file, falls
// back to a password, and finally tries null auth.
func (t *Controller) Authenticate(password, cookiePath string) error {
	switch {
	case cookiePath != "":
		raw, err := os.ReadFile(cookiePath)
		if err != nil {
			return fmt.Errorf("tor: cookie: %w", err)
		}
		_, err = t.cmd("AUTHENTICATE " + hex.EncodeToString(raw))
		return err
	case password != "":
		_, err := t.cmd("AUTHENTICATE " + quote(password))
		return err
	default:
		_, err := t.cmd("AUTHENTICATE")
		return err
	}
}

// AddOnion publishes a v3 onion service forwarding virtPort to target.
//
// Pass an empty privKey to mint a new service; the returned key can be stored
// and passed back later to keep a stable .onion address.
func (t *Controller) AddOnion(privKey string, virtPort int, target string) (serviceID, key string, err error) {
	spec := "NEW:ED25519-V3"
	if privKey != "" {
		spec = privKey
	}
	lines, err := t.cmd(fmt.Sprintf("ADD_ONION %s Port=%d,%s", spec, virtPort, target))
	if err != nil {
		return "", "", err
	}
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "ServiceID="):
			serviceID = strings.TrimPrefix(l, "ServiceID=")
		case strings.HasPrefix(l, "PrivateKey="):
			key = strings.TrimPrefix(l, "PrivateKey=")
		}
	}
	if serviceID == "" {
		return "", "", errors.New("tor: ADD_ONION returned no ServiceID")
	}
	if privKey != "" {
		key = privKey
	}
	return serviceID, key, nil
}

// cmd sends a control command and collects the reply's data lines.
func (t *Controller) cmd(command string) ([]string, error) {
	_ = t.c.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := t.c.Write([]byte(command + "\r\n")); err != nil {
		return nil, err
	}

	var lines []string
	for {
		raw, err := t.br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line := strings.TrimRight(raw, "\r\n")
		if len(line) < 4 {
			return nil, fmt.Errorf("tor: short control reply %q", line)
		}
		code, sep, rest := line[:3], line[3], line[4:]
		if code != "250" {
			return nil, fmt.Errorf("tor: control error %s: %s", code, rest)
		}
		if rest != "OK" {
			lines = append(lines, rest)
		}
		if sep == ' ' {
			return lines, nil
		}
	}
}

func quote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}

func randomAuth() (string, string, error) {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	var a, b [10]byte
	if _, err := rand.Read(a[:]); err != nil {
		return "", "", err
	}
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", err
	}
	return enc.EncodeToString(a[:]), enc.EncodeToString(b[:]), nil
}
