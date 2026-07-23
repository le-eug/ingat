"""
Application-level message framing for ingat's client<->server<->client
relay, layered on top of crypto.handshake's generic length-prefixed
frames.

crypto/handshake.py owns the X25519 key-exchange messages (HELLO_UNAUTH
/ HELLO_AUTH, types 0x01/0x02). This module owns the surrounding
messages needed to actually run the relay -- username announcement,
peer presence, and encrypted chat -- using a disjoint type range
(0x10+) so a reader dispatches on the same leading type byte regardless
of which module produced the frame.
"""

from crypto import handshake
from crypto.cipher import NONCE_LEN

MSG_TYPE_USERNAME = 0x10    # client -> server: my display name
MSG_TYPE_PEER_READY = 0x11  # server -> client: a peer is present, here's their name
MSG_TYPE_PEER_LEFT = 0x12   # server -> client: the peer disconnected
MSG_TYPE_CHAT = 0x13        # client <-> server <-> client: AES-GCM-encrypted chat message


def pack_username(username: str) -> bytes:
    return handshake.pack_frame(bytes([MSG_TYPE_USERNAME]) + username.encode())


def unpack_username(payload: bytes) -> str:
    if not payload or payload[0] != MSG_TYPE_USERNAME:
        raise handshake.FrameError("expected USERNAME frame")
    return payload[1:].decode()


def pack_peer_ready(peer_username: str) -> bytes:
    return handshake.pack_frame(bytes([MSG_TYPE_PEER_READY]) + peer_username.encode())


def unpack_peer_ready(payload: bytes) -> str:
    if not payload or payload[0] != MSG_TYPE_PEER_READY:
        raise handshake.FrameError("expected PEER_READY frame")
    return payload[1:].decode()


def pack_peer_left() -> bytes:
    return handshake.pack_frame(bytes([MSG_TYPE_PEER_LEFT]))


def pack_chat(nonce: bytes, ciphertext: bytes) -> bytes:
    """`ciphertext` is AESGCM's output, i.e. ciphertext with the 16-byte
    tag already appended (see crypto.cipher.encrypt)."""
    if len(nonce) != NONCE_LEN:
        raise ValueError(f"nonce must be {NONCE_LEN} bytes")
    return handshake.pack_frame(bytes([MSG_TYPE_CHAT]) + nonce + ciphertext)


def unpack_chat(payload: bytes) -> tuple[bytes, bytes]:
    if not payload or payload[0] != MSG_TYPE_CHAT:
        raise handshake.FrameError("expected CHAT frame")
    body = payload[1:]
    if len(body) < NONCE_LEN:
        raise handshake.FrameError("CHAT frame too short to contain a nonce")
    return body[:NONCE_LEN], body[NONCE_LEN:]


class FrameBuffer:
    """Accumulates bytes read from a stream socket and yields complete
    frame payloads as they become available, holding back any partial
    frame until more data arrives.
    """

    def __init__(self):
        self._buf = bytearray()

    def feed(self, data: bytes) -> list[bytes]:
        self._buf += data
        payloads = []
        while True:
            try:
                payload, remainder = handshake.unpack_frame(bytes(self._buf))
            except handshake.FrameError:
                break
            payloads.append(payload)
            self._buf = bytearray(remainder)
        return payloads


if __name__ == "__main__":
    # --- pack/unpack round trips ---
    assert unpack_username(handshake.unpack_frame(pack_username("alice"))[0]) == "alice"
    assert unpack_peer_ready(handshake.unpack_frame(pack_peer_ready("bob"))[0]) == "bob"
    payload, _ = handshake.unpack_frame(pack_peer_left())
    assert payload == bytes([MSG_TYPE_PEER_LEFT])
    nonce = bytes(range(NONCE_LEN))
    ct = b"pretend-ciphertext-and-tag"
    got_nonce, got_ct = unpack_chat(handshake.unpack_frame(pack_chat(nonce, ct))[0])
    assert (got_nonce, got_ct) == (nonce, ct)
    print("wire pack/unpack round trips: PASS")

    # --- FrameBuffer: frames split across multiple feed() calls ---
    frame = pack_username("carol")
    fb = FrameBuffer()
    assert fb.feed(frame[:5]) == []          # partial frame: nothing yet
    payloads = fb.feed(frame[5:])            # rest arrives: one payload
    assert len(payloads) == 1
    assert unpack_username(payloads[0]) == "carol"
    print("FrameBuffer partial-read reassembly: PASS")

    # --- FrameBuffer: multiple frames delivered in one feed() call ---
    combined = pack_username("dave") + pack_peer_left()
    fb2 = FrameBuffer()
    payloads = fb2.feed(combined)
    assert len(payloads) == 2
    assert unpack_username(payloads[0]) == "dave"
    assert payloads[1] == bytes([MSG_TYPE_PEER_LEFT])
    print("FrameBuffer multi-frame batch: PASS")
