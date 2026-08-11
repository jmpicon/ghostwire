# Security policy

## Status

**ghostwire has not been independently audited.** It is a new protocol written
by one person. The cryptographic primitives are standard and come from
`golang.org/x/crypto`; the composition around them is not proven. Read
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md), including the list of known
weaknesses, before relying on it.

## Reporting a vulnerability

Report privately. Do not open a public issue for anything that could be used
against current users.

- GitHub private advisory: **Security → Report a vulnerability** on this
  repository (preferred).
- Email: **neural@neural-ghost.com**

Useful reports include what an attacker gains, the conditions required, and
ideally a test case or patch. You will get an acknowledgement within 72 hours
and an assessment within 14 days.

Coordinated disclosure: 90 days, or sooner once a fix is released. If a report
turns out to describe a documented limitation rather than a bug, that will be
said plainly and the documentation improved if it was unclear.

## In scope

- Anything that lets a relay operator learn channel names, membership,
  message content, or message lengths.
- Anything that lets a non-member decrypt, forge, or replay traffic.
- Anything that lets one channel member forge a message attributed to another.
- Key material reaching disk, `argv`, environment, or logs unexpectedly.
- Traffic-analysis distinguishers stronger than those already documented.
- Memory-safety or resource-exhaustion bugs in `gwd`.

## Out of scope

These are documented design limits, not vulnerabilities:

- Global passive adversaries correlating both ends of a Tor circuit.
- Endpoint compromise (keyloggers, malicious binaries, hostile operating
  systems).
- Recovering history after a passphrase is disclosed — there is no forward
  secrecy against passphrase compromise, and the threat model says so.
- Non-repudiation of signed messages.
- A relay operator counting how many connections subscribe to a tag.
- Denial of service by a relay operator against their own relay.

## Supported versions

The tip of `main` and the most recent tagged release. There is no long-term
support branch.
