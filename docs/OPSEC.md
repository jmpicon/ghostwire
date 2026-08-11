# Operational notes

The protocol is the easy part. Most real deanonymisation is operational.

## Passphrases

The channel key is only as strong as the passphrase. Argon2id at 64 MiB buys
you roughly six orders of magnitude against an offline attacker — it does not
rescue `password123`.

- Use a diceware phrase of **five words minimum**, six if the channel outlives
  the week.
- Never reuse a channel passphrase anywhere else.
- Distribute it over a channel that is not the one you are protecting. In
  person, or over an already-trusted encrypted channel.
- Rotate by moving the room: `/part #ops`, then join `#ops-2` with a new
  passphrase. There is no rekey command because there is no server to
  coordinate one.

Channel *names* are also secret material in practice. Do not reuse memorable
names across unrelated groups: someone who guesses both the name and the
passphrase is in, and names are the easier half.

## Identities

The default is ephemeral and that is usually correct. A persistent identity
(`gw keygen` + `-identity`) buys recognisability and costs linkability.

Take a persistent identity when the group must be sure that the person
speaking today is the person who spoke yesterday. Skip it when being one
consistent entity across time is itself the risk.

Verify fingerprints out of band, once, and remember them. The nickname is
decoration; anyone can take yours. The fingerprint after the `#` is what you
check.

## The relay

- Run your own. A relay you do not control is a relay whose operator can count
  your channel's subscribers and censor it.
- Run it somewhere unrelated to your identity, paid for in a way unrelated to
  your identity.
- Do not put it behind Cloudflare, a reverse proxy, or anything else that
  terminates or logs the connection. The point is that nothing between you and
  `gwd` exists.
- `-onion-key` persists the address across restarts, which is convenient and
  makes the relay a stable, findable target. Ephemeral (no `-onion-key`) means
  a new address every restart and no artefact on disk.
- Never expose `gwd` on clearnet in production. It has no transport
  authentication and no TLS by design — the onion service *is* the transport
  security.

## Your machine

- Build from source. Check `go.sum`. A backdoored `gw` binary defeats
  everything in this repository.
- Run it from a terminal that does not log scrollback to disk. Many terminal
  emulators keep a buffer; some shells log more than you expect.
- ghostwire writes nothing, but your OS might: swap, hibernation images, core
  dumps. Encrypt your swap, or disable it.
- `-key` and `#channel:passphrase` put the secret in `argv`, which is readable
  by every process on the box via `/proc`. They exist for automation. For a
  human at a keyboard, use the prompt.
- `/panic` wipes keys and exits immediately with no goodbye. Learn the
  keystroke before you need it.

## Cover traffic

The default (20 s mean, both directions) costs about 200 bytes/second per
connection. That is nothing for a laptop and meaningful for a metered mobile
link.

Turning it off with `-noise 0` makes your session cheaper *and* makes the
moments you are typing visible to anyone watching the encrypted stream. Do not
turn it off to save bandwidth on a link you care about hiding on.

## Group hygiene

- Assume every member logs everything. Signatures are non-repudiable.
- A channel with two members is visibly a two-party conversation to the relay
  operator, even though they cannot tell who or what.
- Silence is invisible. There is no presence protocol, so `/names` only shows
  people who have actually spoken. A quiet member is indistinguishable from an
  absent one — this is deliberate, and it means you cannot verify who is
  listening. Assume more people are in the room than have spoken.
- When a group is done, everyone `/part`s and the passphrase is forgotten.
  There is no archive to clean up because there is no archive.

## Clock

Epoch keys are wall-clock derived. A machine more than an hour out of sync
silently fails to decrypt anything. If a peer sees nothing while others see
traffic, check `timedatectl` before you suspect the crypto.
