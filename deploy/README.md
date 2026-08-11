# Running a relay

A ghostwire relay is stateless, writes nothing, and does no cryptography — all
the expensive work (Argon2id) happens in the client. Its worst-case memory is
roughly `max-conns × 128 KiB` of queued cells.

That has a practical consequence worth stating plainly: **a relay does not need
a server.** A Raspberry Pi, an old thin client, or the smallest VPS on the menu
will carry a channel comfortably. Spend your thinking on *where* it sits, not
on how big it is.

## Choosing where it sits

The onion service means the relay makes only outbound connections. There is no
port to forward, no dynamic DNS, no firewall rule, and CGNAT is irrelevant.
You can run one on a home connection behind a router you do not control.

Whether you *should* is a different question:

| Location | Good | Bad |
|---|---|---|
| Home / SBC | Costs nothing, physically yours, no provider to subpoena, no payment trail | If the hidden service is ever deanonymised, it points at **your home**. Home uptime and consumer ISPs are what they are. |
| Small VPS | Points at a datacentre, not at you. Reliable uptime. | A provider exists, with your payment details, who can be compelled or can simply pull the plug. |
| Someone else's relay | No effort | They count your channel's subscribers and can censor it. Never for anything sensitive. |

For personal use, learning, an alerting sink, or a repo mirror, home is fine
and cheap. For a relay that carries other people's crisis communications,
put it somewhere that is not your house and not the other party's network.

## Option A — docker compose

Tor and the relay, isolated from each other and from the host. The relay
container has no route off the box at all.

```bash
docker compose up -d --build
docker compose exec -T tor cat /var/lib/tor/ghostwire/hostname
```

## Option B — systemd, fronted by the host's tor

The right shape for a box that already runs tor: an SBC, a home server, a VPS.
The relay gets no tor credentials and no filesystem access, because tor
publishes the onion service itself.

**1. Install the binary.** Pick the architecture — 32-bit ARM boards are
common and need `armv7`, not `arm64`:

```bash
uname -m                       # armv7l → armv7 · aarch64 → arm64 · x86_64 → amd64
sudo install -m 0755 gwd-linux-armv7 /usr/local/bin/gwd
```

**2. Tell tor to publish it.** Append to `/etc/tor/torrc`:

```
HiddenServiceDir /var/lib/tor/ghostwire/
HiddenServicePort 1717 127.0.0.1:1717
HiddenServiceVersion 3
```

**3. Keep tor awake.** A tor that has only ever served a SOCKS port enters
*dormant* mode after prolonged client inactivity — which is exactly the state
an idle home server's tor is in when you decide to give it an onion service.
A dormant tor is not a good host for one. Also append:

```
DormantTimeoutEnabled 0
DormantCanceledByStartup 1
```

**4. Start both.** Use `restart`, not `reload`, the first time: a HUP wakes a
dormant tor but is not a reliable way to bring a brand-new hidden service up.

```bash
sudo install -m 0644 gwd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now gwd
sudo systemctl restart tor@default          # or tor.service
sudo cat /var/lib/tor/ghostwire/hostname    # your relay address
```

On Debian and Raspberry Pi OS, `tor@default` reports `enabled-runtime`, which
looks alarming and is not: the enabled `tor.service` wrapper pulls the instance
in at boot. Check `systemctl is-enabled tor.service` instead.

The address is stable as long as `/var/lib/tor/ghostwire/` survives. Delete
that directory to get a new one and leave nothing behind.

## Option C — no configuration at all

`gwd` can mint its own ephemeral onion through the tor control port. Nothing
touches `torrc`, nothing needs root, and the service stops being published the
moment the process exits.

```bash
gwd -onion -tor-cookie /run/tor/control.authcookie
```

This needs `ControlPort 9051` and `CookieAuthentication 1` in `torrc`, and your
user in the group that owns the cookie (`debian-tor` on Debian and Ubuntu —
adding yourself to it requires a re-login before it takes effect).

Add `-onion-key ~/.gw/onion.key` to keep the same address across restarts.

## Sizing

| Setting | Default | Notes |
|---|---|---|
| `-max-conns` | 512 | ~67 MiB worst case. Drop to 128 on a 1 GiB board. |
| `-rate` | 64 cells/s | Per connection. A human types far below this. |
| `-noise` | 20s | Relay→client cover traffic. ~200 B/s per connection. |
| `-idle` | 5m | Silent connections are dropped; clients reconnect. |
| `-stats` | off | Aggregate counters only. There is no per-channel accounting to enable. |

## Verifying it works

`gwd -stats` prints only aggregate counters, so the honest test is to push
traffic through it and watch the numbers move:

```bash
printf 'test\n' | gw pipe -relay <addr>.onion:1717 -join '#smoke' -key 'test passphrase'
```

`in` and `out` should both increase. If `in` moves but `out` does not, the
cells arrived and were dropped — check `-max-conns` and the rate limit.

If nothing moves at all, the failure is transport, not ghostwire: check that
tor bootstrapped to 100% on both ends, and remember that a first connection to
a freshly published onion service can take tens of seconds.

Two traps worth knowing before you spend an evening on them:

**`curl --socks5-hostname telnet://host:1717` tells you nothing.** curl opens
the connection and then blocks reading until `--max-time`, so it exits 28
whether or not it reached anything. Use the real client and read the relay's
counters.

**`cmd | tail` reports `tail`'s exit status, not the client's.** `rc=0` from a
pipeline is not evidence that the send worked. Run the client unpiped, or check
`PIPESTATUS`.

The only trustworthy signal is the relay's `in`/`out` counters moving, measured
before and after.
