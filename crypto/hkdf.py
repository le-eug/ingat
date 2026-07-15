"""
HMAC-SHA256 and HKDF (RFC 5869)

We lean on hashlib.sha256 only for the underlying compression function
(computing a plain SHA-256 digest); the HMAC construction (padding, inner/
outer hashing) and the HKDF extract/expand steps are built manually here,
mainly for learning. Correctness and clarity over performance.
"""

import hashlib

HASH_LEN = 32   # SHA-256 output size in bytes
BLOCK_SIZE = 64  # SHA-256 block size in bytes


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """HMAC-SHA256(key, message), per RFC 2104:
        HMAC(K, m) = H((K' xor opad) || H((K' xor ipad) || m))
    where K' is `key` padded/hashed down to exactly one block.
    """
    # Keys longer than a block are shortened by hashing; keys shorter
    # than a block are zero-padded up to the block size.
    if len(key) > BLOCK_SIZE:
        key = _sha256(key)
    key = key + b"\x00" * (BLOCK_SIZE - len(key))

    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5C for b in key)

    inner = _sha256(ipad + message)
    return _sha256(opad + inner)


def extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract (RFC 5869 section 2.2): PRK = HMAC-Hash(salt, IKM).

    If salt is empty, it is replaced with HashLen zero bytes, per spec.
    """
    if not salt:
        salt = b"\x00" * HASH_LEN
    return hmac_sha256(salt, ikm)


def expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand (RFC 5869 section 2.3): stretch PRK into `length` bytes
    of output keying material (OKM), bound to the given context `info`.

        T(0) = empty string
        T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
        OKM  = T(1) || T(2) || ... truncated to `length` bytes
    """
    max_len = 255 * HASH_LEN
    if length > max_len:
        raise ValueError(f"Cannot expand to more than {max_len} bytes")

    n = -(-length // HASH_LEN)  # ceil(length / HASH_LEN)
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac_sha256(prk, t + info + bytes([i]))
        okm += t
    return okm[:length]


def derive_key(shared_secret: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """Convenience wrapper: HKDF-Extract-then-Expand a symmetric key out
    of a raw shared secret (e.g. an X25519 ECDH output)."""
    prk = extract(salt, shared_secret)
    return expand(prk, info, length)


if __name__ == "__main__":
    # --- RFC 5869 Appendix A test vectors (SHA-256 cases) ---

    # Test Case 1: basic case
    ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    length = 42
    expected_prk = bytes.fromhex(
        "077709362c2e32df0ddc3f0dc47bba63" "90b6c73bb50f9c3122ec844ad7c2b3e5"
    )
    expected_okm = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    prk = extract(salt, ikm)
    okm = expand(prk, info, length)
    assert prk == expected_prk, f"Test 1 PRK mismatch: {prk.hex()}"
    assert okm == expected_okm, f"Test 1 OKM mismatch: {okm.hex()}"
    print("RFC 5869 Test Case 1 (basic): PASS")

    # Test Case 2: longer inputs/outputs, multiple 32-byte chunks
    ikm = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f"
        "303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f"
    )
    salt = bytes.fromhex(
        "606162636465666768696a6b6c6d6e6f"
        "707172737475767778797a7b7c7d7e7f"
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    )
    info = bytes.fromhex(
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
        "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    )
    length = 82
    expected_prk = bytes.fromhex(
        "06a6b88c5853361a06104c9ceb35b45c" "ef760014904671014a193f40c15fc244"
    )
    expected_okm = bytes.fromhex(
        "b11e398dc80327a1c8e7f78c596a4934"
        "4f012eda2d4efad8a050cc4c19afa97c"
        "59045a99cac7827271cb41c65e590e09"
        "da3275600c2f09b8367793a9aca3db71"
        "cc30c58179ec3e87c14c01d5c1f3434f"
        "1d87"
    )
    prk = extract(salt, ikm)
    okm = expand(prk, info, length)
    assert prk == expected_prk, f"Test 2 PRK mismatch: {prk.hex()}"
    assert okm == expected_okm, f"Test 2 OKM mismatch: {okm.hex()}"
    print("RFC 5869 Test Case 2 (longer inputs/outputs): PASS")

    # Test Case 3: zero-length salt and info
    ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    salt = b""
    info = b""
    length = 42
    expected_prk = bytes.fromhex(
        "19ef24a32c717b167f33a91d6f648bdf" "96596776afdb6377ac434c1c293ccb04"
    )
    expected_okm = bytes.fromhex(
        "8da4e775a563c18f715f802a063c5a31"
        "b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8"
    )
    prk = extract(salt, ikm)
    okm = expand(prk, info, length)
    assert prk == expected_prk, f"Test 3 PRK mismatch: {prk.hex()}"
    assert okm == expected_okm, f"Test 3 OKM mismatch: {okm.hex()}"
    print("RFC 5869 Test Case 3 (zero-length salt/info): PASS")

    # --- Sanity check: derive_key end-to-end, as it'd be used with an
    # X25519 shared secret in ingat's handshake ---
    fake_shared_secret = bytes(range(32))
    key = derive_key(fake_shared_secret, salt=b"ingat-salt", info=b"ingat handshake v1", length=32)
    assert len(key) == 32
    print(f"derive_key sanity check: {key.hex()}")
