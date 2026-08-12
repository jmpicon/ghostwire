// Package launch holds the startup decisions shared by every ghostwire
// client — terminal or desktop.
//
// It exists so there is exactly one place that decides whether a connection is
// anonymous. A second copy of that logic is a second chance to get it wrong,
// and the failure mode is silent: the client works perfectly while exposing
// the user's IP address.
package launch

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strings"

	gcrypto "github.com/jmpicon/ghostwire/internal/crypto"
	"github.com/jmpicon/ghostwire/internal/tor"
)

// Transport resolves the dialer for a relay address, refusing to silently
// deanonymise the caller. The bool reports whether the connection goes
// through Tor.
func Transport(relay, socks string, clearnet bool) (tor.DialFunc, bool, error) {
	if strings.TrimSpace(relay) == "" {
		return nil, false, errors.New("no relay: pass -relay <addr> or set GW_RELAY")
	}
	isOnion := tor.IsOnion(relay)

	if clearnet {
		if isOnion {
			return nil, false, errors.New("-clearnet cannot reach a .onion address")
		}
		return tor.Direct(), false, nil
	}
	if !isOnion {
		return nil, false, fmt.Errorf(
			"%q is not a v3 onion address.\n"+
				"ghostwire refuses to connect anonymously to something that is not anonymous.\n"+
				"pass -clearnet if you genuinely mean to expose your IP (lab use only)", relay)
	}
	dial, err := tor.SOCKS(socks, true)
	if err != nil {
		return nil, false, fmt.Errorf("tor SOCKS at %s: %w (is tor running?)", socks, err)
	}
	return dial, true, nil
}

// Identity loads a persistent seed, or mints an ephemeral identity when path
// is empty. Ephemeral is the default everywhere for a reason: it is what makes
// two sessions unlinkable.
func Identity(path string) (*gcrypto.Identity, error) {
	if path == "" {
		return gcrypto.NewIdentity()
	}
	seed, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("identity %s: %w (create one with: gw keygen -o %s)", path, err, path)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("identity %s: expected %d bytes, got %d", path, ed25519.SeedSize, len(seed))
	}
	return gcrypto.IdentityFromSeed(seed)
}

// Env reads an environment variable with a fallback.
func Env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
