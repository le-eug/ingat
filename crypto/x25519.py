"""
X25519 (Curve25519 Diffie-Hellman), implemented from scratch per RFC 7748.

Pure-Python bigint arithmetic, no crypto libraries. Written for learning.
Correctness and clarity over performance or production hardening.

SECURITY NOTE (read before reusing this anywhere real):
This implementation is NOT constant-time. Python's arbitrary-precision
integers do not execute in fixed time for arithmetic ops, and both
`_cswap` (a Python-level branch on the swap bit) and the modular inverse
(`pow(z, p - 2, p)`, whose runtime depends on CPython's bigint
multiplication/exponentiation, which varies with operand size/value) can
leak timing information correlated with the secret scalar. A real-world
implementation needs constant-time field arithmetic and a branchless
conditional swap (typically via bitmasking in fixed-width integers, often
in C or with hardware support). This code is for learning the algorithm,
not for deployment.
"""

import os

# --- Curve25519 field/curve parameters (RFC 7748 section 4.1) ---
P = 2 ** 255 - 19          # field prime p = 2^255 - 19
A24 = 121665               # (486662 - 2) / 4, the Montgomery curve constant
BITS = 255                 # bit length used by the ladder for X25519


def _cswap(swap: int, a: int, b: int) -> tuple[int, int]:
    """Conditionally swap (a, b) if swap == 1, else leave them unchanged.

    NOT constant-time: this is a plain Python conditional, so its
    execution time (and any branch-predictor/microarchitectural effects)
    can differ depending on the value of `swap`. A real implementation
    would do this via arithmetic/bitmasking on fixed-width words so the
    CPU takes the same path regardless of the secret bit.
    """
    if swap:
        return b, a
    return a, b


def _decode_little_endian(b: bytes) -> int:
    return int.from_bytes(b, "little")


def _decode_u_coordinate(u: bytes) -> int:
    """Decode a 32-byte little-endian u-coordinate, masking the high bit
    of the last byte per RFC 7748 section 5 (since p uses only 255 bits,
    the top bit of a 256-bit encoding is ignored/cleared on decode)."""
    u_list = bytearray(u)
    u_list[31] &= 0x7F
    return _decode_little_endian(bytes(u_list))


def _encode_u_coordinate(u: int) -> bytes:
    return (u % P).to_bytes(32, "little")


def _decode_scalar(k: bytes) -> int:
    """Clamp a 32-byte scalar per RFC 7748 section 5:
      - clear the low 3 bits (force the scalar to be a multiple of 8,
        i.e. clear the curve's cofactor so small-subgroup points are
        neutralized),
      - clear bit 255 (keep the scalar below 2^255),
      - set bit 254 (force the ladder to always run a fixed number of
        iterations / keep the top bit set for the ladder invariant).
    """
    k_list = bytearray(k)
    k_list[0] &= 248        # clear bottom 3 bits of the first byte
    k_list[31] &= 127       # clear bit 255 (top bit of last byte)
    k_list[31] |= 64        # set bit 254
    return _decode_little_endian(bytes(k_list))


def _inv(z: int) -> int:
    """Modular inverse of z mod p via Fermat's little theorem: z^(p-2) = z^-1 (mod p).

    NOT constant-time: Python's pow(base, exp, mod) for bigints does not
    guarantee execution time independent of the operands' bit patterns
    (its runtime tracks the size/value of the numbers involved), so this
    can leak information through timing side channels.
    """
    return pow(z, P - 2, P)


def x25519(scalar: bytes, u_coord: bytes) -> bytes:
    """Core X25519 scalar multiplication: compute scalar * u_coord on the
    Montgomery curve, via the Montgomery ladder (RFC 7748 section 5).

    Args:
        scalar: 32-byte little-endian scalar (will be clamped).
        u_coord: 32-byte little-endian u-coordinate of the input point.

    Returns:
        32-byte little-endian u-coordinate of the resulting point.
    """
    k = _decode_scalar(scalar)
    x1 = _decode_u_coordinate(u_coord)

    x2, z2 = 1, 0     # "point at infinity" (identity) in projective coords
    x3, z3 = x1, 1    # running point, starts at the input u-coordinate
    swap = 0

    for t in range(BITS - 1, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        x2, x3 = _cswap(swap, x2, x3)
        z2, z3 = _cswap(swap, z2, z3)
        swap = k_t

        A = (x2 + z2) % P
        AA = (A * A) % P
        B = (x2 - z2) % P
        BB = (B * B) % P
        E = (AA - BB) % P
        C = (x3 + z3) % P
        D = (x3 - z3) % P
        DA = (D * A) % P
        CB = (C * B) % P
        x3 = (DA + CB) % P
        x3 = (x3 * x3) % P
        z3 = (DA - CB) % P
        z3 = (x1 * (z3 * z3)) % P
        x2 = (AA * BB) % P
        z2 = (E * (AA + A24 * E)) % P

    x2, x3 = _cswap(swap, x2, x3)
    z2, z3 = _cswap(swap, z2, z3)

    result = (x2 * _inv(z2)) % P
    return _encode_u_coordinate(result)


# Base point u = 9, as defined for Curve25519 (RFC 7748 section 4.1).
BASE_POINT_U = (9).to_bytes(32, "little")


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an X25519 keypair: a random 32-byte private scalar and its
    corresponding public key (private scalar times the base point u=9)."""
    private_key = os.urandom(32)
    public_key = x25519(private_key, BASE_POINT_U)
    return private_key, public_key


def shared_secret(my_priv: bytes, their_pub: bytes) -> bytes:
    """Compute the ECDH shared secret: my_priv * their_pub."""
    return x25519(my_priv, their_pub)


if __name__ == "__main__":
    # --- RFC 7748 section 5.2 test vector (first X25519 test case) ---
    scalar = bytes.fromhex(
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
    )
    u_in = bytes.fromhex(
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
    )
    expected = bytes.fromhex(
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
    )

    result = x25519(scalar, u_in)
    assert result == expected, (
        f"RFC 7748 test vector FAILED: got {result.hex()}, expected {expected.hex()}"
    )
    print("RFC 7748 5.2 test vector: PASS")
    print(f"  scalar   = {scalar.hex()}")
    print(f"  u        = {u_in.hex()}")
    print(f"  result   = {result.hex()}")

    # --- Alice/Bob round-trip: both sides must derive the same secret ---
    alice_priv, alice_pub = generate_keypair()
    bob_priv, bob_pub = generate_keypair()

    alice_secret = shared_secret(alice_priv, bob_pub)
    bob_secret = shared_secret(bob_priv, alice_pub)

    assert alice_secret == bob_secret, "Alice and Bob derived different shared secrets!"
    print("Alice/Bob ECDH round-trip: PASS")
    print(f"  alice_pub     = {alice_pub.hex()}")
    print(f"  bob_pub       = {bob_pub.hex()}")
    print(f"  shared secret = {alice_secret.hex()}")
