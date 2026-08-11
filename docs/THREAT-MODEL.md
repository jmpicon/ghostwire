# Threat model

Read this before you trust ghostwire with anything that matters. A privacy
tool that only advertises its strengths is a liability.

## Who this protects you from

**The relay operator.** This is the design centre. An operator with root on the
relay box, full packet capture, and a debugger attached to `gwd` learns:

- that N anonymous Tor circuits are connected;
- a set of 32-byte tags those circuits subscribed to;
- that fixed-size cells arrived and were fanned out.

They do not learn your IP, your identity, the channel names, the membership,
the message lengths, the message boundaries, or a single byte of content. They
cannot join a channel they observe traffic on, because the tag is not the key.
Compelling them to hand over "the logs" produces nothing, because there are no
logs and no disk state to produce.

**Anyone who seizes the relay afterwards.** `gwd` never writes to disk. There
is no database, no message store, no user table. Powering it off destroys
everything it ever held.

**A network observer near you.** They see a Tor connection. Cell padding means
they cannot infer message sizes; Poisson-scheduled cover traffic means they
cannot infer *whether you are typing at all*, only that a ghostwire session is
open. Send jitter means keystroke timing does not survive to the wire.

**Someone who joins the channel later.** Channel keys rotate hourly. A key
extracted from a running process's memory stops decrypting new traffic at the
next epoch boundary, and never decrypts traffic from previous epochs.

**A member trying to impersonate another member.** Everyone in a channel holds
the same symmetric key, so ghostwire signs every message with a per-identity
Ed25519 key. Nicknames are forgeable; the 8-character fingerprint next to each
nickname is not.

**Correlation across sessions.** Identities are ephemeral by default: a new
keypair per run, never written to disk. Nothing links today's session to
yesterday's unless you explicitly opt into `-identity`.

## Who this does NOT protect you from

**A global passive adversary.** Someone who can observe both ends of the Tor
network simultaneously can correlate your traffic by timing, the same way they
can against Tor itself. Cover traffic raises the cost; it does not eliminate
the attack. If your adversary is a state intelligence service with taps on
tier-1 backbones, ghostwire does not solve your problem and neither does
anything else you can install.

**Your endpoint.** A keylogger, a screen recorder, a malicious `gw` binary, or
someone reading over your shoulder defeats all of this instantly. ghostwire
protects data in transit and metadata at the relay. It cannot protect a
compromised machine. Verify your binaries; build from source if you can.

**A compromised passphrase.** <a id="forward-secrecy"></a>Epoch keys derive
deterministically from the Argon2id output of the passphrase. Someone who
learns the passphrase and has archived ciphertext can derive *every* epoch key
and read the whole history they captured.

This is the honest limit of ghostwire's forward secrecy. Signal's double
ratchet gives real per-message forward secrecy; ghostwire's epochs only limit
the damage from a *key scraped out of RAM*, not from a *leaked passphrase*.
Rotate passphrases, and treat channels as disposable. Proper group forward
secrecy needs an MLS-style ratchet, which is on the roadmap and not yet built.

**Deniability.** Message signatures are non-repudiable. A channel member who
logs everything they receive holds cryptographic proof that a given
*fingerprint* said a given thing. Because the default identity is ephemeral
and never leaves RAM, that proof binds to a key that no longer exists and was
never tied to you — but it is proof, and if you use `-identity` you are
building exactly the persistent, attributable record ghostwire otherwise
avoids. Choose deliberately.

**Traffic confirmation by a relay operator who is also in the channel.** If
your adversary joins the channel legitimately (they guessed or were given the
passphrase) *and* runs the relay, they can correlate which circuit sends the
cells that decrypt to which fingerprint. Do not run channels on relays
operated by people you are hiding from.

**Membership counting.** The relay knows how many connections subscribe to a
tag. It does not know who they are, but a channel with exactly two subscribers
is visibly a two-party conversation.

**A small anonymity set.** This is the risk people underestimate. Being one of
a few dozen ghostwire users is itself identifying. Tor hides *that you connect
to a specific service*, but running unusual software on a monitored machine is
a signal. If a forensic examiner finds `gw` on your laptop, the tool's mere
presence is evidence, even though its contents are not.

**Legal compulsion against you.** No cryptography survives someone who can
compel you personally. `/panic` wipes keys in RAM immediately; it does nothing
about what you have already told other people, or about your own memory.

## Cryptographic choices and why

| Choice | Rationale |
|---|---|
| Argon2id, 64 MiB, t=3, p=4 | Channel security rests on a human-chosen passphrase, so the KDF must be genuinely expensive. This is the main defence against offline guessing. |
| XChaCha20-Poly1305 | 192-bit nonces make random nonce generation safe without any counter state — important because there is no session handshake to synchronise counters. |
| Ed25519 signatures | Small, fast, no parameter choices to get wrong, and constant-time in the standard library. |
| BLAKE2b for tags and fingerprints | Keyed hashing without an HMAC construction, and no length-extension concerns. |
| HKDF-SHA256 for epochs | Standard, well-analysed, and separates the epoch key from the master key cleanly. |
| Fixed 512-byte cells | Length is the metadata channel that survives encryption. Removing it entirely is cheaper than trying to obscure it. |
| Poisson cover traffic | A fixed-interval heartbeat is trivially separable from real traffic. Exponential inter-arrival times make real messages statistically indistinguishable from padding. |
| Relay echoes to the sender | Equalises each connection's inbound and outbound cell rate and gives a delivery receipt at zero state cost. |

## Known weaknesses in this implementation

Listed here because they are real and because you deserve to know before you
find them yourself:

1. **No forward secrecy against passphrase compromise.** See above. This is the
   most significant gap versus Signal.
2. **No post-compromise security.** If an attacker gets the passphrase, they
   stay in until humans rotate it out of band.
3. **Epoch boundaries are wall-clock.** A host with a badly wrong clock (more
   than an hour off) silently fails to decrypt. There is no NTP dependency by
   design, but there is also no warning.
4. **No relay authentication.** A hostile relay cannot read your traffic, but
   it can drop it, reorder cells within a channel, or refuse service. The
   replay guard and per-message signatures bound the damage to censorship, not
   forgery.
5. **`Zeroize` is best effort.** Go's garbage collector may have already copied
   key material elsewhere in the heap. Memory is not locked with `mlock`.
6. **Unaudited.** One author, new protocol, no external cryptographic review.
   The primitives are standard; the composition is not proven.

## If you need more than this

Use Signal for interpersonal messaging where a phone number is acceptable —
it is audited, it has real forward secrecy, and it has an anonymity set of
hundreds of millions. Use SecureDrop for whistleblowing to an organisation.
Use Tails or Qubes if your endpoint is the concern.

ghostwire is for the case none of those cover: a persistent group room with no
account, no directory, no operator who could betray you even under compulsion,
and no artefact left behind when it is over.
