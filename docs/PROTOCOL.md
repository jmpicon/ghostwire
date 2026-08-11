# ghostwire wire protocol v1

Everything here is normative for interoperability. If you write a second
implementation, this is the contract.

## 0. Layers

```
  ┌──────────────────────────────────────────────────┐
  │ inner message   signed Ed25519, plaintext        │  end to end
  ├──────────────────────────────────────────────────┤
  │ sealed payload  XChaCha20-Poly1305, epoch key    │  end to end
  ├──────────────────────────────────────────────────┤
  │ DATA payload    chanID ‖ flags ‖ fragment        │  relay-visible
  ├──────────────────────────────────────────────────┤
  │ cell            512 bytes, fixed, padded         │  relay-visible
  ├──────────────────────────────────────────────────┤
  │ TCP over Tor v3 onion service                    │  network
  └──────────────────────────────────────────────────┘
```

The relay parses only the bottom two layers. It has no key material at any
point in its lifetime.

## 1. Cell

Every octet that crosses the socket belongs to a cell. A cell is **always**
exactly 512 bytes, in both directions, for every message type.

```
 0        1        2        3        4                              512
 +--------+--------+--------+--------+------------------------------+
 | ver    | type   | length (BE16)   | payload ‖ random padding     |
 +--------+--------+--------+--------+------------------------------+
```

| Field | Size | Notes |
|---|---|---|
| `ver` | 1 | `0x01`. A cell with any other value is dropped and the peer disconnected. |
| `type` | 1 | see below |
| `length` | 2 | big endian, `0 … 508` |
| `payload` | `length` | type-specific |
| `padding` | `508 - length` | **cryptographic random**, never zeroes |

Padding must come from a CSPRNG. Zero padding would make cell contents
compressible and would leak `length` to anyone observing an encrypted tunnel
that compresses.

### Types

| Value | Name | Direction | Payload |
|---|---|---|---|
| `0x00` | `NOISE` | both | empty; cover traffic, silently discarded |
| `0x01` | `HELLO` | both | 1 byte protocol version |
| `0x02` | `JOIN` | client → relay | 32-byte channel id |
| `0x03` | `PART` | client → relay | 32-byte channel id |
| `0x04` | `DATA` | both | see §2 |
| `0x05` | `PING` | client → relay | empty |
| `0x06` | `PONG` | relay → client | empty |
| `0x07` | `BYE` | client → relay | empty |
| `0x08` | `ERR` | relay → client | short ASCII reason |

`NOISE` is value `0x00` so that a zeroed buffer decodes to "nothing happened"
rather than to a meaningful command.

## 2. DATA payload

```
 0                              32       33                      ≤508
 +------------------------------+--------+------------------------+
 | channel id (32)              | flags  | fragment               |
 +------------------------------+--------+------------------------+
```

- `flags` bit `0x01` = `MORE`: another fragment follows. All other bits MUST be
  zero.
- Maximum fragment size is `508 - 33 = 475` bytes.

A sealed payload longer than 475 bytes is split across consecutive `DATA`
cells with the same channel id. **The relay does not reassemble.** It forwards
each cell independently, in arrival order, and therefore never observes a
message boundary — only a stream of equal-sized cells.

Receivers MUST bound reassembly buffers (the reference client uses 256 KiB per
channel) and MUST discard the partial buffer when the bound is exceeded.

## 3. Channel derivation

A channel is not created, it is *derived*. There is no registry.

```
name'   = "#" + lowercase(trim(name) with leading '#' stripped)
salt    = BLAKE2b-256("ghostwire/v1/channel-salt|" ‖ name')[0..16]
master  = Argon2id(passphrase, salt, t=3, m=65536 KiB, p=4, len=32)

chanID  = BLAKE2b-256-keyed(key=master, "ghostwire/v1/channel-id")
```

`chanID` is the only channel-related value the relay ever sees. It is a keyed
hash of a constant under the master key: recovering the channel name from it
requires breaking Argon2id and BLAKE2b.

Two participants agree on a channel purely by agreeing on `(name, passphrase)`
out of band. Nobody — including a relay operator with full packet capture —
can enumerate channels, confirm a guessed channel name, or prove a given
channel exists on their relay without first guessing the passphrase.

## 4. Epoch keys

```
epoch     = floor(unix_seconds / 3600)
epochKey  = HKDF-SHA256(ikm=master, salt=chanID,
                        info="ghostwire/v1/epoch" ‖ BE64(epoch))[0..32]
```

The channel silently rekeys every hour. Receivers MUST attempt
`{epoch, epoch+1, epoch-1}` so that clock skew and hour boundaries never drop a
message. A ciphertext more than one epoch away MUST NOT decrypt.

## 5. Sealing

```
nonce  = 24 random bytes
aad    = chanID ‖ BE64(epoch)
sealed = nonce ‖ XChaCha20-Poly1305-Seal(epochKey, nonce, inner, aad)
```

Binding the AAD to `(chanID, epoch)` means a ciphertext cannot be replayed
into a different channel or a different epoch even by someone who holds a
different channel's key.

## 6. Inner message

```
 0     1     2                34         42     43
 +-----+-----+----------------+----------+-----+---------+
 | ver | kind| sender pub (32)| ts BE64  | nl  | nick    |
 +-----+-----+----------------+----------+-----+---------+
       | body length BE16 | body | signature (64)        |
       +------------------+------+-----------------------+
```

| Field | Notes |
|---|---|
| `ver` | `0x01` |
| `kind` | `1` message, `2` action (`/me`), `3` presence |
| `sender pub` | Ed25519 public key, 32 bytes |
| `ts` | unix seconds, **truncated to 10 s** |
| `nl` / `nick` | 0–32 bytes UTF-8, cosmetic only |
| `body` | ≤ 8192 bytes UTF-8 |
| `signature` | Ed25519 over every preceding byte |

Presence bodies are exactly `join`, `part`, or `nick <previous nick>`.

Receivers MUST:

1. verify the signature before interpreting any field;
2. reject a message whose timestamp is more than 15 minutes from local time;
3. drop a payload whose BLAKE2b digest was already accepted within that window.

Timestamps are quantised to 10 seconds because a precise clock is a
fingerprint, and because nothing in a chat protocol needs better.

**Why sign at all?** Everyone in the channel holds the same symmetric key, so
without a signature any member could put words in another member's mouth.
The signature is over the *inner* plaintext, so the relay cannot see it. The
tradeoff is discussed under "deniability" in the threat model.

## 7. Relay behaviour

The relay MUST:

- forward a `DATA` cell to **every** connection subscribed to that `chanID`,
  **including the sender** (this equalises per-connection rates and doubles as
  a delivery receipt);
- refuse to forward `DATA` for a `chanID` the sender has not joined;
- treat `JOIN` as idempotent and never acknowledge it (an acknowledgement is a
  channel-existence oracle);
- emit `NOISE` on its own Poisson schedule to every connection;
- drop cells rather than block when a connection's output queue is full;
- disconnect a peer that exceeds its cell rate, with no explanation.

The relay MUST NOT:

- write per-connection or per-channel records to disk or to a log;
- expose any interface that enumerates connections or channels;
- retain anything across a restart.

## 8. Transport

The reference client refuses any relay address that is not a 56-character v3
onion, unless `-clearnet` is passed explicitly. Each session uses fresh random
SOCKS5 credentials so that tor assigns an isolated circuit; two sessions from
one host cannot be correlated by circuit reuse.

## 9. Constants

| Name | Value |
|---|---|
| `CellSize` | 512 |
| `MaxPayload` | 508 |
| `MaxChunk` | 475 |
| `ChanIDLen` | 32 |
| `EpochSeconds` | 3600 |
| Argon2id | t=3, m=65536 KiB, p=4, 32-byte output |
| `TimeGranularity` | 10 s |
| `FreshnessWindow` | 15 min |
| Default noise mean | 20 s (both directions) |
| Default send jitter | 400 ms |
| Default port | 1717 |
