# ingat handshake protocol

This document describes the wire format for ingat's key-agreement
("handshake") messages, implemented in `crypto/handshake.py`. It covers
byte layout only — the actual cryptography lives in `crypto/x25519.py`
(ECDH), `crypto/hkdf.py` (key derivation), `crypto/cipher.py` (message
encryption), and a future `crypto/ed25519.py` (identity signatures, not
yet implemented).

## Framing

Every handshake message is wrapped in a generic length-prefixed frame:

```
+----------------------+------------------------+
| length (4 bytes, BE)  | payload (length bytes) |
+----------------------+------------------------+
```

- `length` is an unsigned 32-bit big-endian integer giving the size of
  `payload` in bytes.
- A reader on a byte stream (e.g. a TCP socket) reads 4 bytes to learn
  `length`, then reads exactly that many more bytes to get one complete
  message, regardless of that message's internal structure. This is what
  lets the payload format change (e.g. a longer authenticated variant)
  without changing how messages are located on the wire.

`crypto/handshake.py` exposes this layer as `pack_frame(payload)` and
`unpack_frame(buf) -> (payload, remainder)`.

## Message types

The first byte of every payload is a message-type tag:

| Tag    | Name           | Meaning                                        |
|--------|----------------|-------------------------------------------------|
| `0x01` | `HELLO_UNAUTH` | Bare X25519 ephemeral public key, no identity   |
| `0x02` | `HELLO_AUTH`   | Ephemeral public key + identity key + signature |

### `HELLO_UNAUTH` (37-byte frame)

```
+------+------------------------+
| type | ephemeral_pub          |
| (1B) | (32B, X25519 pubkey)   |
+------+------------------------+
```

Total payload: 33 bytes (1 + 32). Total frame (with length prefix): 37 bytes.

Each party generates a fresh X25519 keypair for the session
(`crypto.x25519.generate_keypair`) and sends only the public half. Both
sides run `crypto.x25519.shared_secret` against the peer's ephemeral
public key to get a raw ECDH secret, then feed it through
`crypto.hkdf.derive_key` to get a symmetric key for `crypto.cipher`.

**This is deliberately unauthenticated.** Nothing in this message binds
the ephemeral key to who sent it — an active network attacker sitting
between the two parties can intercept both `HELLO_UNAUTH` frames,
substitute their own ephemeral public keys, and complete two separate
ECDH exchanges (one with each victim) without either party detecting
anything at the protocol level. This is the textbook machine-in-the-middle
weakness of raw, unauthenticated Diffie-Hellman, and it's intentionally
what ingat's MITM demo (`src/mitm.py`) targets: the demo proxies
`HELLO_UNAUTH` frames and swaps the embedded key, showing why key
authentication is necessary.

`HELLO_UNAUTH` is implemented and is what the current handshake uses.

### `HELLO_AUTH` (133-byte frame) — format defined, not yet wired up

```
+------+------------------------+------------------------+------------------------+
| type | ephemeral_pub          | identity_pub           | signature              |
| (1B) | (32B, X25519 pubkey)   | (32B, Ed25519 pubkey)  | (64B, Ed25519 sig)     |
+------+------------------------+------------------------+------------------------+
```

Total payload: 129 bytes (1 + 32 + 32 + 64). Total frame (with length
prefix): 133 bytes.

`signature` is an Ed25519 signature, produced by the sender's long-term
identity key, over the exact byte string `ephemeral_pub || identity_pub`
(see `crypto.handshake.signed_data_for`). A receiver who already trusts
`identity_pub` (e.g. has it pinned, or verified it out-of-band) can
verify the signature before accepting `ephemeral_pub`, which stops the
substitution attack described above: an attacker without the sender's
identity private key cannot forge a valid signature over a swapped-in
ephemeral key.

This message type's wire format is defined now so `crypto/handshake.py`
doesn't need to change shape later, but **signing and verification are
not implemented** — that depends on a `crypto/ed25519.py` module that
doesn't exist yet in this codebase. `pack_hello_auth`/`unpack_hello_auth`
only pack/unpack the three byte fields; they take `signature` as an
opaque `bytes` value and never compute or check it.

## Design notes

- **No separate version byte.** The message-type tag doubles as the
  format discriminator for now. If the wire format needs to change in a
  way that isn't just "add a new message type" (e.g. a backward-
  incompatible change to an existing message), a dedicated version byte
  should be added at that point — it isn't needed yet.
- **Fixed-size fields, no inner length prefixes.** Every field
  (ephemeral_pub, identity_pub, signature) has a fixed size dictated by
  the algorithm producing it, so only the outer frame needs a length
  prefix. This keeps parsing simple: once the type byte is known, the
  rest of the payload is a fixed-size struct.
- **No encryption at this layer.** Handshake messages are sent in the
  clear; only the ephemeral (and, for `HELLO_AUTH`, identity) *public*
  keys are transmitted, so confidentiality isn't required for the
  handshake itself. Confidentiality for chat messages, once a shared
  key is derived, is handled by `crypto/cipher.py` (AES-256-GCM).
