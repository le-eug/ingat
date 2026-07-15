"""
Handshake wire format for ingat's key-agreement messages.

This module only defines byte layout (pack/unpack) — it does not do any
networking (no sockets) and does not perform cryptographic operations
(no ECDH, no signing/verification). Callers are expected to generate the
X25519 ephemeral keypair (crypto.x25519), and eventually sign with
Ed25519, then hand the resulting bytes to the pack_* functions here.

Two message types are defined:

  HELLO_UNAUTH  - ephemeral public key only. No identity binding, so a
                  network attacker can swap it for their own key without
                  either party noticing. This is deliberately built
                  first and is what ingat's MITM demo targets: it shows
                  why raw, unauthenticated ECDH is vulnerable to an
                  active machine-in-the-middle.

  HELLO_AUTH    - ephemeral public key + identity public key + an
                  Ed25519 signature (by the identity key) over
                  (ephemeral_pub || identity_pub). This binds the
                  ephemeral key to a long-term identity so a receiver
                  who already trusts that identity key can detect
                  substitution. The wire format is defined now so it's
                  ready to wire up once crypto/ed25519.py exists; this
                  module does not implement signing/verification itself.

See PROTOCOL.md for the full format writeup.
"""

import struct

X25519_PUB_LEN = 32
ED25519_PUB_LEN = 32
ED25519_SIG_LEN = 64

MSG_TYPE_HELLO_UNAUTH = 0x01
MSG_TYPE_HELLO_AUTH = 0x02

_LEN_PREFIX = struct.Struct(">I")  # 4-byte big-endian unsigned length prefix


class FrameError(ValueError):
    """Raised when a buffer cannot be parsed as a valid length-prefixed frame."""


def pack_frame(payload: bytes) -> bytes:
    """Wrap `payload` in a 4-byte big-endian length prefix.

    This is the generic framing layer: on a byte stream (e.g. TCP) it
    lets a reader know exactly how many bytes make up one message,
    independent of what that message's internal layout is. It's what
    lets the handshake format evolve later (e.g. HELLO_AUTH's larger
    payload) without changing how frames are located on the wire.
    """
    return _LEN_PREFIX.pack(len(payload)) + payload


def unpack_frame(buf: bytes) -> tuple[bytes, bytes]:
    """Extract one length-prefixed frame from the front of `buf`.

    Returns (payload, remainder) so a caller reading from a stream can
    keep parsing subsequent frames out of `remainder`. Raises FrameError
    if `buf` does not yet contain one complete frame (the caller should
    read more bytes and retry).
    """
    if len(buf) < _LEN_PREFIX.size:
        raise FrameError("buffer too short to contain a length prefix")
    (length,) = _LEN_PREFIX.unpack_from(buf, 0)
    end = _LEN_PREFIX.size + length
    if len(buf) < end:
        raise FrameError(f"buffer has {len(buf)} bytes, frame needs {end}")
    return buf[_LEN_PREFIX.size:end], buf[end:]


def signed_data_for(ephemeral_pub: bytes, identity_pub: bytes) -> bytes:
    """The exact byte string an Ed25519 signature is computed/verified
    over in HELLO_AUTH: ephemeral_pub || identity_pub. Centralized here
    so signing and verification code can't drift apart on the format.
    """
    if len(ephemeral_pub) != X25519_PUB_LEN:
        raise ValueError(f"ephemeral_pub must be {X25519_PUB_LEN} bytes")
    if len(identity_pub) != ED25519_PUB_LEN:
        raise ValueError(f"identity_pub must be {ED25519_PUB_LEN} bytes")
    return ephemeral_pub + identity_pub


# --- HELLO_UNAUTH: type (1B) || ephemeral_pub (32B) ---

def pack_hello_unauth(ephemeral_pub: bytes) -> bytes:
    """Pack an unauthenticated hello frame, ready to write to the wire."""
    if len(ephemeral_pub) != X25519_PUB_LEN:
        raise ValueError(f"ephemeral_pub must be {X25519_PUB_LEN} bytes")
    payload = bytes([MSG_TYPE_HELLO_UNAUTH]) + ephemeral_pub
    return pack_frame(payload)


def unpack_hello_unauth(frame: bytes) -> bytes:
    """Unpack a HELLO_UNAUTH frame (as produced by pack_hello_unauth) and
    return the ephemeral public key. Raises FrameError on malformed input
    or a type-byte mismatch.
    """
    payload, remainder = unpack_frame(frame)
    if remainder:
        raise FrameError(f"{len(remainder)} unexpected trailing bytes after frame")
    if len(payload) != 1 + X25519_PUB_LEN:
        raise FrameError(f"HELLO_UNAUTH payload must be {1 + X25519_PUB_LEN} bytes")
    if payload[0] != MSG_TYPE_HELLO_UNAUTH:
        raise FrameError(f"expected HELLO_UNAUTH type byte {MSG_TYPE_HELLO_UNAUTH:#x}, got {payload[0]:#x}")
    return payload[1:]


# --- HELLO_AUTH: type (1B) || ephemeral_pub (32B) || identity_pub (32B) || signature (64B) ---

def pack_hello_auth(ephemeral_pub: bytes, identity_pub: bytes, signature: bytes) -> bytes:
    """Pack an authenticated hello frame. `signature` must already be a
    valid Ed25519 signature over signed_data_for(ephemeral_pub, identity_pub)
    — this function does not verify or compute it.
    """
    if len(ephemeral_pub) != X25519_PUB_LEN:
        raise ValueError(f"ephemeral_pub must be {X25519_PUB_LEN} bytes")
    if len(identity_pub) != ED25519_PUB_LEN:
        raise ValueError(f"identity_pub must be {ED25519_PUB_LEN} bytes")
    if len(signature) != ED25519_SIG_LEN:
        raise ValueError(f"signature must be {ED25519_SIG_LEN} bytes")
    payload = bytes([MSG_TYPE_HELLO_AUTH]) + ephemeral_pub + identity_pub + signature
    return pack_frame(payload)


def unpack_hello_auth(frame: bytes) -> tuple[bytes, bytes, bytes]:
    """Unpack a HELLO_AUTH frame and return (ephemeral_pub, identity_pub,
    signature). Does NOT verify the signature — that requires
    crypto/ed25519.py, which this module intentionally has no dependency
    on. Raises FrameError on malformed input or a type-byte mismatch.
    """
    payload, remainder = unpack_frame(frame)
    if remainder:
        raise FrameError(f"{len(remainder)} unexpected trailing bytes after frame")
    expected_len = 1 + X25519_PUB_LEN + ED25519_PUB_LEN + ED25519_SIG_LEN
    if len(payload) != expected_len:
        raise FrameError(f"HELLO_AUTH payload must be {expected_len} bytes")
    if payload[0] != MSG_TYPE_HELLO_AUTH:
        raise FrameError(f"expected HELLO_AUTH type byte {MSG_TYPE_HELLO_AUTH:#x}, got {payload[0]:#x}")
    i = 1
    ephemeral_pub = payload[i:i + X25519_PUB_LEN]
    i += X25519_PUB_LEN
    identity_pub = payload[i:i + ED25519_PUB_LEN]
    i += ED25519_PUB_LEN
    signature = payload[i:i + ED25519_SIG_LEN]
    return ephemeral_pub, identity_pub, signature


def peek_msg_type(frame: bytes) -> int:
    """Return the message-type byte of a frame without fully unpacking
    it. Useful for a receiver (or a MITM proxy) that must branch on
    which HELLO variant it received before knowing which unpack_* to call.
    """
    payload, _ = unpack_frame(frame)
    if not payload:
        raise FrameError("empty payload has no message type")
    return payload[0]


if __name__ == "__main__":
    import os

    # --- HELLO_UNAUTH round-trip ---
    ephemeral_pub = os.urandom(X25519_PUB_LEN)
    frame = pack_hello_unauth(ephemeral_pub)
    assert peek_msg_type(frame) == MSG_TYPE_HELLO_UNAUTH
    recovered = unpack_hello_unauth(frame)
    assert recovered == ephemeral_pub
    print("HELLO_UNAUTH pack/unpack round-trip: PASS")
    print(f"  frame length = {len(frame)} bytes "
          f"(4 length prefix + 1 type + {X25519_PUB_LEN} ephemeral pub)")

    # --- HELLO_AUTH round-trip ---
    identity_pub = os.urandom(ED25519_PUB_LEN)
    fake_signature = os.urandom(ED25519_SIG_LEN)  # crypto/ed25519.py doesn't exist yet
    frame = pack_hello_auth(ephemeral_pub, identity_pub, fake_signature)
    assert peek_msg_type(frame) == MSG_TYPE_HELLO_AUTH
    got_eph, got_id, got_sig = unpack_hello_auth(frame)
    assert (got_eph, got_id, got_sig) == (ephemeral_pub, identity_pub, fake_signature)
    print("HELLO_AUTH pack/unpack round-trip: PASS")
    print(f"  frame length = {len(frame)} bytes "
          f"(4 length prefix + 1 type + {X25519_PUB_LEN} ephemeral + "
          f"{ED25519_PUB_LEN} identity + {ED25519_SIG_LEN} signature)")

    # --- signed_data_for is exactly ephemeral_pub || identity_pub ---
    assert signed_data_for(ephemeral_pub, identity_pub) == ephemeral_pub + identity_pub
    print("signed_data_for layout check: PASS")

    # --- Two frames back-to-back on one buffer (simulating stream reads) ---
    frame_a = pack_hello_unauth(os.urandom(X25519_PUB_LEN))
    frame_b = pack_hello_unauth(os.urandom(X25519_PUB_LEN))
    buf = frame_a + frame_b
    payload_a, rest = unpack_frame(buf)
    payload_b, rest2 = unpack_frame(rest)
    assert rest2 == b""
    assert payload_a + b"" == frame_a[4:]  # payload matches what was packed (minus length prefix)
    print("Back-to-back frame parsing: PASS")

    # --- Incomplete buffer raises FrameError (caller should keep reading) ---
    try:
        unpack_frame(frame_a[:-1])
        raise AssertionError("truncated frame was accepted!")
    except FrameError:
        print("Truncated frame detection: PASS")

    # --- Wrong type byte is rejected by the type-specific unpackers ---
    try:
        unpack_hello_auth(frame_a)  # frame_a is actually a HELLO_UNAUTH
        raise AssertionError("HELLO_UNAUTH frame was accepted as HELLO_AUTH!")
    except FrameError:
        print("Type mismatch detection: PASS")
