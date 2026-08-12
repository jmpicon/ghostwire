// Command gw is the ghostwire client: an IRC-shaped terminal for channels
// that no server can enumerate, over a transport that no relay can trace.
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/jmpicon/ghostwire/internal/client"
	gcrypto "github.com/jmpicon/ghostwire/internal/crypto"
	"github.com/jmpicon/ghostwire/internal/launch"
	"github.com/jmpicon/ghostwire/internal/tor"
	"github.com/jmpicon/ghostwire/internal/ui"
)

var version = "dev"

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

type options struct {
	relay     string
	socks     string
	clearnet  bool
	nick      string
	identity  string
	joins     stringList
	key       string
	noiseMean time.Duration
	jitter    time.Duration
	noRetry   bool
	version   bool
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "keygen":
			keygen(os.Args[2:])
			return
		case "pipe":
			runPipe(os.Args[2:])
			return
		case "tail":
			runTail(os.Args[2:])
			return
		case "version":
			fmt.Printf("gw %s\n", version)
			return
		case "help", "-h", "--help":
			usage()
			return
		}
	}

	opts := parseFlags("gw", os.Args[1:])
	if opts.version {
		fmt.Printf("gw %s\n", version)
		return
	}
	if err := run(opts); err != nil {
		fatal("%v", err)
	}
}

func parseFlags(name string, args []string) *options {
	o := &options{}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.StringVar(&o.relay, "relay", env("GW_RELAY", ""), "relay address, normally <56chars>.onion:1717")
	fs.StringVar(&o.socks, "tor", env("GW_TOR_SOCKS", tor.DefaultSOCKS), "tor SOCKS5 address")
	fs.BoolVar(&o.clearnet, "clearnet", false, "connect without tor (exposes your IP to the relay)")
	fs.StringVar(&o.nick, "nick", env("GW_NICK", "anon"), "cosmetic display name")
	fs.StringVar(&o.identity, "identity", env("GW_IDENTITY", ""), "persistent identity seed file (default: ephemeral, never written)")
	fs.Var(&o.joins, "join", "channel to join at startup (repeatable)")
	fs.StringVar(&o.key, "key", env("GW_KEY", ""), "channel passphrase (prefer the interactive prompt; argv is world-readable)")
	fs.DurationVar(&o.noiseMean, "noise", 20*time.Second, "mean cover-traffic interval (0 disables padding — not recommended)")
	fs.DurationVar(&o.jitter, "jitter", 400*time.Millisecond, "maximum random delay before sending, to blur keystroke timing")
	fs.BoolVar(&o.noRetry, "no-reconnect", false, "exit instead of rebuilding the circuit after a drop")
	fs.BoolVar(&o.version, "version", false, "print version and exit")
	fs.Usage = usage
	_ = fs.Parse(args)
	return o
}

func run(o *options) error {
	dial, viaTor, err := transport(o)
	if err != nil {
		return err
	}
	id, err := identity(o.identity)
	if err != nil {
		return err
	}

	autojoin, err := collectJoins(o)
	if err != nil {
		return err
	}

	cli, err := client.New(client.Config{
		Addr:       o.relay,
		Dial:       dial,
		Identity:   id,
		Nick:       o.nick,
		NoiseMean:  o.noiseMean,
		SendJitter: o.jitter,
		Reconnect:  !o.noRetry,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() { _ = cli.Run(ctx) }()

	tui := ui.New(cli, o.relay, viaTor, stop)
	return tui.Run(ctx, autojoin)
}

// transport picks the dialer and refuses to silently deanonymise you.
// The decision itself lives in internal/launch so the terminal and desktop
// clients cannot drift apart on it.
func transport(o *options) (tor.DialFunc, bool, error) {
	dial, viaTor, err := launch.Transport(o.relay, o.socks, o.clearnet)
	if err == nil && !viaTor {
		fmt.Fprintln(os.Stderr, "warning: -clearnet. the relay will see your IP address.")
	}
	return dial, viaTor, err
}

func identity(path string) (*gcrypto.Identity, error) {
	return launch.Identity(path)
}

func collectJoins(o *options) ([]ui.Autojoin, error) {
	var out []ui.Autojoin
	for _, raw := range o.joins {
		name := raw
		pass := o.key
		// "#room:passphrase" is supported for scripts, at the usual cost of
		// putting a secret in argv.
		if i := strings.Index(raw, ":"); i > 0 {
			name, pass = raw[:i], raw[i+1:]
		}
		if pass == "" {
			p, err := askPassphrase(fmt.Sprintf("passphrase for %s: ", gcrypto.NormalizeChannel(name)))
			if err != nil {
				return nil, err
			}
			pass = p
		}
		if pass == "" {
			return nil, fmt.Errorf("empty passphrase for %s", name)
		}
		out = append(out, ui.Autojoin{Name: name, Passphrase: pass})
	}
	return out, nil
}

func askPassphrase(prompt string) (string, error) {
	fd := int(syscall.Stdin)
	if !term.IsTerminal(fd) {
		return "", errors.New("no terminal available to read a passphrase; use -key or GW_KEY")
	}
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// ---- gw keygen ------------------------------------------------------------

func keygen(args []string) {
	fs := flag.NewFlagSet("gw keygen", flag.ExitOnError)
	out := fs.String("o", "", "write the 32-byte seed here (0600)")
	_ = fs.Parse(args)

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		fatal("rand: %v", err)
	}
	id, err := gcrypto.IdentityFromSeed(seed)
	if err != nil {
		fatal("%v", err)
	}

	if *out == "" {
		fmt.Fprintln(os.Stderr, "refusing to print a private seed to a terminal. use -o <file>.")
		fmt.Fprintf(os.Stderr, "\nnote: a persistent identity links every session you use it in.\n")
		fmt.Fprintf(os.Stderr, "the default (no -identity) is ephemeral and unlinkable. that is\n")
		fmt.Fprintf(os.Stderr, "usually what you want.\n")
		os.Exit(1)
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o700); err != nil {
		fatal("mkdir: %v", err)
	}
	if _, err := os.Stat(*out); err == nil {
		fatal("%s already exists; refusing to overwrite an identity", *out)
	}
	if err := os.WriteFile(*out, seed, 0o600); err != nil {
		fatal("write: %v", err)
	}
	fmt.Printf("identity written to %s\nfingerprint: %s\n", *out, id.Fingerprint())
	fmt.Println("\nback it up or lose it. there is no recovery and nobody to ask.")
}

// ---- gw pipe --------------------------------------------------------------

// runPipe reads stdin and sends each line to a channel. It exists so that a
// script, a sensor or a dead man's switch can speak into a channel without a
// terminal.
func runPipe(args []string) {
	o := parseFlags("gw pipe", args)
	if len(o.joins) != 1 {
		fatal("gw pipe needs exactly one -join <#channel>")
	}

	dial, _, err := transport(o)
	if err != nil {
		fatal("%v", err)
	}
	id, err := gcrypto.NewIdentity()
	if err != nil {
		fatal("%v", err)
	}
	joins, err := collectJoins(o)
	if err != nil {
		fatal("%v", err)
	}

	cli, err := client.New(client.Config{
		Addr:       o.relay,
		Dial:       dial,
		Identity:   id,
		Nick:       o.nick,
		NoiseMean:  o.noiseMean,
		SendJitter: o.jitter,
		Reconnect:  !o.noRetry,
	})
	if err != nil {
		fatal("%v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() { _ = cli.Run(ctx) }()

	// Building a Tor circuit to an onion service routinely takes tens of
	// seconds. Reading stdin before the link is up would silently discard
	// the first lines, so wait for it.
	connected := make(chan struct{})
	go func() {
		var once sync.Once
		for ev := range cli.Events() {
			if ev.Kind == client.EvConnected {
				once.Do(func() { close(connected) })
			}
		}
	}()

	select {
	case <-connected:
	case <-ctx.Done():
		return
	case <-time.After(3 * time.Minute):
		fatal("timed out building a circuit to %s", o.relay)
	}

	if err := cli.Join(joins[0].Name, joins[0].Passphrase); err != nil {
		fatal("join: %v", err)
	}

	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64<<10), 8<<10)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r\n")
		if line == "" {
			continue
		}
		if err := cli.Say(joins[0].Name, line); err != nil {
			fmt.Fprintf(os.Stderr, "gw pipe: %v\n", err)
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "gw pipe: stdin: %v\n", err)
	}
	// Let the jitter delay elapse, then flush whatever is still queued.
	time.Sleep(o.jitter)
	cli.Drain(30 * time.Second)
	cli.Close()
}

// ---- gw tail --------------------------------------------------------------

// runTail is the mirror of gw pipe: it joins channels and writes every message
// it receives to stdout, one line each, and nothing else. Everything that is
// not channel content — link state, presence, errors — goes to stderr, so the
// stream stays pipeable into grep, a log shipper or another gw pipe.
func runTail(args []string) {
	o := parseFlags("gw tail", args)
	if len(o.joins) == 0 {
		fatal("gw tail needs at least one -join <#channel>")
	}

	dial, _, err := transport(o)
	if err != nil {
		fatal("%v", err)
	}
	id, err := identity(o.identity)
	if err != nil {
		fatal("%v", err)
	}
	joins, err := collectJoins(o)
	if err != nil {
		fatal("%v", err)
	}

	cli, err := client.New(client.Config{
		Addr:       o.relay,
		Dial:       dial,
		Identity:   id,
		Nick:       o.nick,
		NoiseMean:  o.noiseMean,
		SendJitter: o.jitter,
		Reconnect:  !o.noRetry,
	})
	if err != nil {
		fatal("%v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() { _ = cli.Run(ctx) }()

	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	var joined bool
	for ev := range cli.Events() {
		switch ev.Kind {
		case client.EvConnected:
			fmt.Fprintf(os.Stderr, "gw tail: link up → %s\n", ev.Text)
			if !joined {
				joined = true
				for _, j := range joins {
					if err := cli.Join(j.Name, j.Passphrase); err != nil {
						fmt.Fprintf(os.Stderr, "gw tail: join %s: %v\n", j.Name, err)
					}
				}
			}
		case client.EvDisconnected:
			fmt.Fprintf(os.Stderr, "gw tail: link down (%s)\n", ev.Text)
		case client.EvError:
			fmt.Fprintf(os.Stderr, "gw tail: %s\n", ev.Text)
		case client.EvPresence:
			fmt.Fprintf(os.Stderr, "gw tail: %s %s#%s %s\n", ev.Channel,
				ev.Msg.Nick, gcrypto.Short(ev.Msg.Fingerprint()), ev.Msg.Body)
		case client.EvMessage:
			// Line-buffered so a reader downstream sees each alert as it
			// lands rather than when a 4 KiB buffer happens to fill.
			fmt.Fprintf(out, "%s %s %s#%s %s\n",
				ev.Msg.Sent.Local().Format("2006-01-02 15:04"),
				ev.Channel, ev.Msg.Nick, gcrypto.Short(ev.Msg.Fingerprint()),
				ev.Msg.Body)
			out.Flush()
		}
	}
}

func env(k, def string) string { return launch.Env(k, def) }

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gw: "+format+"\n", args...)
	os.Exit(1)
}

func usage() {
	fmt.Fprint(os.Stderr, `gw — ghostwire client

  IRC that forgets you existed.

usage:
  gw -relay <addr>.onion:1717 -join '#room'
  gw -relay <addr>.onion:1717 -join '#room' -nick ghost -identity ~/.gw/id
  gw keygen -o ~/.gw/id
  echo "alert" | gw pipe -relay <addr>.onion:1717 -join '#ops'
  gw tail -relay <addr>.onion:1717 -join '#ops' | grep -i critical

subcommands:
  keygen    mint a persistent identity seed (default is ephemeral)
  pipe      send stdin lines into a channel, no terminal required
  tail      print received messages to stdout, no terminal required
  version   print version

flags:
  -relay        relay address (env GW_RELAY)
  -join         channel to enter at startup, repeatable
  -key          channel passphrase (env GW_KEY; prefer the prompt)
  -nick         cosmetic display name (env GW_NICK)
  -identity     persistent seed file (env GW_IDENTITY)
  -tor          tor SOCKS5 address (env GW_TOR_SOCKS, default 127.0.0.1:9050)
  -clearnet     no tor. the relay sees your IP. lab use only.
  -noise        mean cover-traffic interval (default 20s, 0 disables)
  -jitter       max random send delay (default 400ms)
  -no-reconnect exit on link failure instead of rebuilding the circuit

  Channel keys come from the name plus the passphrase. Nobody, including the
  relay, can enumerate channels or confirm that one exists.
`)
}
