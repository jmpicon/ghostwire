<div align="center">

```
        __               __             _
  ___ _/ /  ___  ___ ___/ /_    __ __ __(_)______
 / _ `/ _ \/ _ \(_-</ __/ |/|/ // // __/ -_)
 \_, /_//_/\___/___/\__/|__,__/ \_,_/_/  \___/
/___/
```

**IRC that forgets you existed.**

no accounts · no phone numbers · no logs · no server-side identity · onion-only

[![ci](https://github.com/jmpicon/ghostwire/actions/workflows/ci.yml/badge.svg)](https://github.com/jmpicon/ghostwire/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![go](https://img.shields.io/badge/go-1.25-00ADD8.svg)](go.mod)

</div>

---

## What this is

The old IRC channels worked because they were *rooms*, not *contact lists*. You
showed up, you talked, you left, and nothing about you persisted anywhere.
Modern messengers rebuilt the room on top of an account — and an account is a
handle the world can pull on.

ghostwire is that room again, with the metadata surgically removed.

- **No identity to seize.** No phone number, no email, no username registry, no
  account. Your identity is an Ed25519 key generated in RAM at startup and
  destroyed at exit. Two sessions are unlinkable unless you deliberately reuse
  a key.
- **No server that knows anything.** The relay is blind: it sees anonymous Tor
  circuits, opaque 32-byte channel tags, and fixed-size ciphertext. It cannot
  name a channel, read a message, enumerate members, or tell you apart.
- **No channel directory.** Channels are *derived*, not *created*. `#ops` +
  passphrase → Argon2id → a key and a blinded routing tag. There is no `/list`,
  because there is nothing to list. A relay operator cannot prove a given
  channel exists on their own box.
- **No length, no timing.** Every byte on the wire is a 512-byte cell. Real
  messages, cover traffic and silence are the same shape. Padding arrives on a
  Poisson schedule, and sends are jittered, so keystrokes do not survive to the
  network.
- **No disk.** The relay writes nothing. The client writes nothing. `/panic`
  wipes every key in memory and kills the process.

## Where it actually sits

Honest comparison. Signal is excellent cryptography with a strong ratchet and a
real audit history; ghostwire is not trying to beat it at that game. It is
trying to beat it at *metadata*.

| | Telegram | Signal | ghostwire |
|---|---|---|---|
| Registration | phone number | phone number | none |
| Server knows who you are | yes (account) | yes (account, sealed sender) | **nothing to know** |
| Server knows your IP | yes | yes | **no — onion only** |
| Server knows the group exists | yes | yes | **no — blinded tag** |
| Group crypto | none by default | ratchet | XChaCha20-Poly1305, hourly epoch |
| Message length hidden | no | partly | **yes — fixed 512B cells** |
| Cover traffic | no | no | **yes — Poisson padding** |
| Forward secrecy | partial | **yes, per-message** | epoch-level only ([why](docs/THREAT-MODEL.md#forward-secrecy)) |
| Independently audited | partly | **yes** | **no — assume bugs** |
| Anonymity set | large | large | **small — see below** |

The two rows where ghostwire loses are the two you must actually weigh. Read
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) before trusting this with anything
that matters. A small user base is itself a deanonymisation risk: being one of
forty ghostwire users is more identifying than being one of a billion
WhatsApp users.

## Build

```bash
git clone https://github.com/jmpicon/ghostwire
cd ghostwire
make            # builds bin/gw and bin/gwd
make test       # unit + integration, with -race
```

Single static binaries, no runtime, no dependencies:

```bash
make cross      # linux/darwin/windows × amd64/arm64 into dist/
```

## Run a relay

You need a local `tor` with its control port open. `gwd` mints its own
ephemeral v3 onion service — no `torrc` edits, no `HiddenServiceDir`, no root.

```bash
gwd -onion -tor-cookie /run/tor/control.authcookie

  onion service live:

    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion:1717
```

Keep a stable address across restarts:

```bash
gwd -onion -onion-key ~/.gw/onion.key -tor-cookie /run/tor/control.authcookie
```

Or with Docker, tor included:

```bash
cd deploy && docker compose up -d && make -C .. onion   # prints the address
```

## Connect

```bash
gw -relay xxxx…xxxx.onion:1717 -join '#ops'
passphrase for #ops: ********
```

That is the whole enrolment process. There is no signup, no invite link, no
QR code, no verification SMS. Whoever has the relay address, the channel name
and the passphrase is in the room; whoever does not, cannot even observe that
the room exists.

```
 tor  1:*ghostwire 2:#ops  s4qwc5ib  ghost
┌ #ops ─────────────────────────────────────────┬ who spoke ──┐
│ 21:14 → ghost#s4qwc5ib is here                │ 2 heard     │
│ 21:15 ghost#s4qwc5ib is the drop still live?  │             │
│ 21:15 anon#7fk2mq9x  moved it. new tag below. │ •ghost      │
│ 21:16 * anon#7fk2mq9x rotates the key         │   s4qwc5ib  │
│                                               │  anon       │
│                                               │   7fk2mq9x  │
└───────────────────────────────────────────────┴─────────────┘
» _
```

### Commands

```
/join #room [pass]   derive a channel and enter it
/part [#room]        leave and destroy the key in RAM
/msg #room <text>    speak into another window
/me <text>           action line
/names               who has actually spoken here
/whois <nick|fp>     everything knowable about a member (it is not much)
/nick <name>         change the cosmetic label
/keys                show your own fingerprint
/win <n> /next /prev switch windows   (^N ^P, ^L clears)
/quit                announce, close, exit
/panic               wipe every key in memory and die immediately
```

Nicknames are decoration and anyone can take yours. **Fingerprints are the
identity.** Every line is signed, so a nickname collision is loud and obvious:
the 8-char tag after the `#` will not match.

### Scripting

`gw pipe` feeds stdin into a channel — sensors, cron jobs, alerting, a dead
man's switch:

```bash
journalctl -f -u sshd | gw pipe -relay xxxx.onion:1717 -join '#alerts'
```

### Persistent identity (opt-in, think first)

```bash
gw keygen -o ~/.gw/id
gw -identity ~/.gw/id -relay xxxx.onion:1717 -join '#ops'
```

A persistent key means people can recognise you across sessions. It also means
they can *correlate* you across sessions. The default is ephemeral for a
reason.

## How it works

| Layer | Mechanism |
|---|---|
| Transport | Tor v3 onion service; per-session SOCKS credentials force circuit isolation |
| Framing | 512-byte cells, always; random padding; fragmentation is opaque to the relay |
| Channel key | `Argon2id(passphrase, blake2b(name))` → 64 MiB, t=3, p=4 |
| Routing tag | `blake2b-keyed(master, "channel-id")` — sent in clear, reveals nothing |
| Epoch key | `HKDF-SHA256(master, id, epoch)`, rotates hourly, ±1 epoch skew tolerated |
| Sealing | XChaCha20-Poly1305, AAD binds ciphertext to (channel, epoch) |
| Authenticity | Ed25519 over the whole inner message; a key-holder cannot forge a peer |
| Anti-replay | 15-minute freshness window + payload digest cache |
| Cover traffic | Poisson-scheduled noise cells, both directions, 20s mean |

Full wire format: [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Security posture

**This code has not been audited.** It is a clean-room implementation by one
person. The primitives are standard and come from `golang.org/x/crypto`, but
the protocol around them is new, and new protocols are wrong until proven
otherwise. Treat it as a serious tool with unproven edges, and read
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) — especially the section on what
ghostwire explicitly does **not** defend against (global passive adversaries,
endpoint compromise, and a compromised passphrase).

Vulnerability reports: [SECURITY.md](SECURITY.md).

## Roadmap

- [ ] MLS-style group ratchet for real per-message forward secrecy
- [ ] 1:1 messages with X3DH + double ratchet
- [ ] Embedded Tor (drop the external daemon dependency)
- [ ] Multi-relay fan-out so no single relay sees a whole channel
- [ ] Reproducible builds and signed releases
- [ ] External cryptographic review

## Legal

ghostwire is a privacy tool, in the same family as Tor, GPG and OTR. It exists
for people who need to talk without building a permanent record of who they
talked to: journalists and their sources, incident responders working an active
compromise, people under surveillance they did not consent to.

Anonymity technology is legal in most jurisdictions and it is your
responsibility to know whether it is legal in yours. Do not use this to commit
crimes; the author will not help you if you do.

## License

[AGPL-3.0](LICENSE). If you run a modified ghostwire relay as a service, your
users get the right to your source. A privacy tool you cannot inspect is a
privacy tool you should not trust.
