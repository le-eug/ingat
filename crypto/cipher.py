"""
AES-256-GCM message layer.

Unlike x25519.py and hkdf.py, this module deliberately does NOT
reimplement AES-GCM from scratch. AES's S-box/round structure and GCM's
GHASH authentication are both easy to get subtly wrong (timing leaks from
table-lookup S-boxes, GHASH carryless-multiplication bugs, nonce/counter
mistakes), and getting them wrong silently breaks confidentiality or
authenticity. That complexity buys little narrative value for a course
project compared to x25519/hkdf, so here we lean on the `cryptography`
library's audited AEAD implementation and focus the "from scratch" budget
where it teaches more: field arithmetic and KDF construction.
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_LEN = 32     # AES-256 key size in bytes
NONCE_LEN = 12   # standard GCM nonce size in bytes


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> tuple[bytes, bytes]:
    """Encrypt `plaintext` with AES-256-GCM under a fresh random nonce.

    Returns (nonce, ciphertext_with_tag): the 16-byte authentication tag
    is appended to the ciphertext by AESGCM.encrypt, so both must be kept
    and passed to decrypt() together.
    """
    if len(key) != KEY_LEN:
        raise ValueError(f"key must be {KEY_LEN} bytes, got {len(key)}")

    nonce = os.urandom(NONCE_LEN)  # must be unique per message under a given key
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext_with_tag


def decrypt(key: bytes, nonce: bytes, ct: bytes, associated_data: bytes = b"") -> bytes:
    """Decrypt and verify ciphertext produced by encrypt().

    Raises cryptography.exceptions.InvalidTag if the ciphertext,
    associated_data, or tag has been tampered with.
    """
    if len(key) != KEY_LEN:
        raise ValueError(f"key must be {KEY_LEN} bytes, got {len(key)}")
    if len(nonce) != NONCE_LEN:
        raise ValueError(f"nonce must be {NONCE_LEN} bytes, got {len(nonce)}")

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, associated_data)


if __name__ == "__main__":
    from cryptography.exceptions import InvalidTag

    key = os.urandom(KEY_LEN)
    plaintext = b"the eagle flies at midnight"
    aad = b"channel:general"

    # --- Round-trip ---
    nonce, ct = encrypt(key, plaintext, aad)
    recovered = decrypt(key, nonce, ct, aad)
    assert recovered == plaintext, "round-trip failed"
    assert len(nonce) == NONCE_LEN
    print("Round-trip encrypt/decrypt: PASS")

    # --- Unique nonce per message ---
    nonce2, ct2 = encrypt(key, plaintext, aad)
    assert nonce != nonce2, "nonces collided across messages"
    print("Nonce uniqueness check: PASS")

    # --- Tamper detection: flip a ciphertext byte, decryption must fail ---
    tampered = bytearray(ct)
    tampered[0] ^= 0x01
    try:
        decrypt(key, nonce, bytes(tampered), aad)
        raise AssertionError("tampered ciphertext was accepted!")
    except InvalidTag:
        print("Tamper detection (ciphertext): PASS")

    # --- Tamper detection: flip an associated_data byte, decryption must fail ---
    try:
        decrypt(key, nonce, ct, associated_data=b"channel:DIFFERENT")
        raise AssertionError("tampered associated_data was accepted!")
    except InvalidTag:
        print("Tamper detection (associated_data): PASS")
