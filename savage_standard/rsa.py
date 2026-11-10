"""RSASSA-PKCS1-v1_5 signatures with SHA-256 (RFC 8017), Savage-original,
Python standard library only.

Why RSA and not Ed25519 here: the estate law is stdlib-only, and this
scheme is exactly implementable with Python's built-in integer math —
key generation is Miller-Rabin primality + modular inverse, signing and
verification are one modular exponentiation each around a fixed,
byte-exact EMSA-PKCS1-v1_5 encoding whose SHA-256 DigestInfo prefix is a
published constant (asserted in the test suite). There is no curve
arithmetic, no point decompression, and no cofactor edge case to get
subtly wrong. Signatures produced here interoperate with any conforming
RSASSA-PKCS1-v1_5 verifier (cross-checked against OpenSSL in
development).

Honest limits, stated once and repeated in GROUND_TRUTH.md:
- This is a CLASSICAL scheme. It is NOT post-quantum. It is not a
  substitute for the ML-DSA-87 (FIPS 204) leg named in CEROS receipts;
  that leg remains not-built.
- The implementation is not constant-time. Verification uses only the
  public key (no secret, no timing concern). Signing runs on the
  operator's own machine over non-secret message bytes; the private
  exponent operation is the exposure and is the operator's accepted
  risk for a local, offline signing tool — the same posture as the
  estate's other local tools.
- Key sizes below 2048 bits are refused for signing keys in the custody
  layer (``signing.py``); this module enforces a 1024-bit floor so unit
  tests can run fast with explicitly test-only keys.
"""
from __future__ import annotations

import hashlib
import hmac
import math
import secrets

# DER prefix of the DigestInfo for SHA-256 (RFC 8017 §9.2, note 1):
# SEQUENCE { SEQUENCE { OID sha256, NULL }, OCTET STRING (32 bytes) }
SHA256_DIGESTINFO_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420")

PUBLIC_EXPONENT = 65537


def _small_primes(limit: int = 2000) -> list:
    sieve = bytearray(b"\x01") * (limit + 1)
    sieve[0:2] = b"\x00\x00"
    for i in range(2, int(limit ** 0.5) + 1):
        if sieve[i]:
            sieve[i * i::i] = b"\x00" * len(sieve[i * i::i])
    return [i for i, is_p in enumerate(sieve) if is_p]


_SMALL_PRIMES = _small_primes()


def _is_probable_prime(n: int, rounds: int = 16) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    # Write n - 1 = 2**r * d with d odd.
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    while True:
        cand = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(cand):
            return cand


def generate_keypair(bits: int = 2048) -> dict:
    """Generate an RSA keypair. Returns dict with int fields
    n, e, d, p, q and ``bits`` (the modulus size)."""
    if bits < 1024:
        raise ValueError("refusing to generate an RSA key below 1024 bits")
    e = PUBLIC_EXPONENT
    p_bits = bits // 2
    q_bits = bits - p_bits
    while True:
        p = _generate_prime(p_bits)
        q = _generate_prime(q_bits)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        lam = math.lcm(p - 1, q - 1)
        if math.gcd(e, lam) != 1:
            continue
        d = pow(e, -1, lam)
        return {"n": n, "e": e, "d": d, "p": p, "q": q, "bits": bits}


def emsa_encode(message: bytes, em_len: int) -> bytes:
    """EMSA-PKCS1-v1_5 encoding of SHA-256(message) into em_len bytes."""
    digest = hashlib.sha256(message).digest()
    t = SHA256_DIGESTINFO_PREFIX + digest
    if em_len < len(t) + 11:
        raise ValueError("intended encoded message length too short")
    ps = b"\xff" * (em_len - len(t) - 3)
    return b"\x00\x01" + ps + b"\x00" + t


def _key_bytes(n: int) -> int:
    return (n.bit_length() + 7) // 8


def sign(private_key: dict, message: bytes) -> bytes:
    """RSASSA-PKCS1-v1_5 signature over message (SHA-256 inside)."""
    n, d = private_key["n"], private_key["d"]
    k = _key_bytes(n)
    em = emsa_encode(message, k)
    m = int.from_bytes(em, "big")
    s = pow(m, d, n)
    return s.to_bytes(k, "big")


def verify(public_key: dict, message: bytes, signature: bytes) -> bool:
    """True iff signature is a valid RSASSA-PKCS1-v1_5/SHA-256 signature
    of message under public_key ({n, e}). Never raises on bad input."""
    try:
        n, e = int(public_key["n"]), int(public_key["e"])
        k = _key_bytes(n)
        if len(signature) != k:
            return False
        s = int.from_bytes(signature, "big")
        if s >= n:
            return False
        em = pow(s, e, n).to_bytes(k, "big")
        expected = emsa_encode(message, k)
        return hmac.compare_digest(em, expected)
    except Exception:
        return False
